/*
 * simulator-operations.c
 *
 *  Created on: Mar 9, 2019
 *      Author: parallels
 */

#include "simulator-operations.h"
#include "sysrepo.h"
#include "sysrepo/values.h"
#include <string.h>
#include <math.h>
#include <linux/limits.h>

#include "utils.h"

#define LINE_BUFSIZE 128

static 	CURL *curl; //share the same curl connection for communicating with the Docker Engine API
static 	CURL *curl_odl; //share the same curl connection for mounting servers in ODL

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

static void set_curl_common_info()
{
	struct curl_slist *chunk = NULL;
	chunk = curl_slist_append(chunk, "Content-Type: application/json");
	chunk = curl_slist_append(chunk, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

	curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/var/run/docker.sock");

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_odl, CURLOPT_CONNECTTIMEOUT, 2L); // seconds timeout for a connection
    curl_easy_setopt(curl_odl, CURLOPT_TIMEOUT, 5L); //seconds timeout for an operation

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
}

static void set_curl_common_info_odl()
{
	struct curl_slist *chunk = NULL;
	chunk = curl_slist_append(chunk, "Content-Type: application/xml");
	chunk = curl_slist_append(chunk, "Accept: application/xml");

    curl_easy_setopt(curl_odl, CURLOPT_HTTPHEADER, chunk);

    curl_easy_setopt(curl_odl, CURLOPT_CONNECTTIMEOUT, 2L); // seconds timeout for a connection
    curl_easy_setopt(curl_odl, CURLOPT_TIMEOUT, 5L); //seconds timeout for an operation

    curl_easy_setopt(curl_odl, CURLOPT_VERBOSE, 1L);
}

static cJSON* get_docker_container_bindings(void)
{
	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	CURLcode res;

	curl_easy_reset(curl);
	set_curl_common_info();

	char url[100];
	sprintf(url, "http:/v%s/containers/NTS_Manager/json", getenv("DOCKER_ENGINE_VERSION"));

	curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		return NULL;
	}
	else
	{
		cJSON *json_response = cJSON_Parse(curl_response_mem.memory);

		printf("%lu bytes retrieved\n", (unsigned long)curl_response_mem.size);

		if (json_response == NULL)
		{
			printf("Could not parse JSON response for url=\"%s\"\n", url);
			return NULL;
		}

		cJSON *hostConfig = cJSON_GetObjectItemCaseSensitive(json_response, "HostConfig");

		if (hostConfig == NULL)
		{
			printf("Could not get HostConfig object\n");
			return NULL;
		}

		cJSON *binds = cJSON_GetObjectItemCaseSensitive(hostConfig, "Binds");

		if (binds == NULL)
		{
			printf("Could not get Binds object\n");
			return NULL;
		}

		cJSON *bindsCopy = cJSON_Duplicate(binds, 1);

	    cJSON_Delete(json_response);

		return bindsCopy;
	}

	return NULL;
}

static char* create_docker_container_curl(int base_netconf_port, cJSON* managerBinds)
{
	if (managerBinds == NULL)
	{
		printf("Could not retrieve JSON object: Binds\n");
		return NULL;
	}
	cJSON *binds = cJSON_Duplicate(managerBinds, 1);

	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	CURLcode res;

	curl_easy_reset(curl);
	set_curl_common_info();

	char url[100];
	sprintf(url, "http:/v%s/containers/create", getenv("DOCKER_ENGINE_VERSION"));

	// the docker image name to be used is defined in the Dockerfile of the NTS Manager,
	// under the MODELS_IMAGE env variable
	char models_var[50];
	sprintf(models_var, "%s", getenv("MODELS_IMAGE"));

	curl_easy_setopt(curl, CURLOPT_URL, url);

    cJSON *postDataJson = cJSON_CreateObject();

    if (cJSON_AddStringToObject(postDataJson, "Image", models_var) == NULL)
	{
    	printf("Could not create JSON object: Image\n");
		return NULL;
	}

    cJSON *hostConfig = cJSON_CreateObject();
    if (hostConfig == NULL)
	{
    	printf("Could not create JSON object: HostConfig\n");
		return NULL;
	}

    cJSON_AddItemToObject(postDataJson, "HostConfig", hostConfig);

    cJSON *portBindings = cJSON_CreateObject();
    if (portBindings == NULL)
	{
    	printf("Could not create JSON object: PortBindings\n");
		return NULL;
	}

    cJSON_AddItemToObject(hostConfig, "PortBindings", portBindings);

    for (int i = 0; i < NETCONF_CONNECTIONS_PER_DEVICE; ++i)
    {
    	cJSON *port = cJSON_CreateArray();
		if (port == NULL)
		{
	    	printf("Could not create JSON object: port\n");
			return NULL;
		}

		char dockerContainerPort[20];
		sprintf(dockerContainerPort, "%d/tcp", 830 + i);

	    cJSON_AddItemToObject(portBindings, dockerContainerPort, port);

	    cJSON *hostPort = cJSON_CreateObject();
	    if (hostPort == NULL)
		{
	    	printf("Could not create JSON object: HostPort\n");
			return NULL;
		}

	    char dockerHostPort[10];
	    sprintf(dockerHostPort, "%d", base_netconf_port + i);
	    if (cJSON_AddStringToObject(hostPort, "HostPort", dockerHostPort) == NULL)
	    {
	    	printf("Could not create JSON object: HostPortString\n");
	    	return NULL;
	    }
	    if (cJSON_AddStringToObject(hostPort, "HostIp", getenv("NTS_IP")) == NULL)
	    {
	    	printf("Could not create JSON object: HostIpString\n");
	    	return NULL;
	    }

	    cJSON_AddItemToArray(port, hostPort);
    }

    cJSON *labels = cJSON_CreateObject();
    if (labels == NULL)
	{
    	printf("Could not create JSON object: Labels\n");
		return NULL;
	}

    cJSON_AddItemToObject(postDataJson, "Labels", labels);

    if (cJSON_AddStringToObject(labels, "NTS", "") == NULL)
    {
    	printf("Could not create JSON object: NTS\n");
    	return NULL;
    }

    cJSON *env_variables_array = cJSON_CreateArray();
    if (env_variables_array == NULL)
	{
    	printf("Could not create JSON object: Env array\n");
		return NULL;
	}

    cJSON_AddItemToObject(postDataJson, "Env", env_variables_array);

    char environment_var[50];
    sprintf(environment_var, "NTS_IP=%s", getenv("NTS_IP"));

    cJSON *env_var_obj = cJSON_CreateString(environment_var);
    if (env_var_obj == NULL)
	{
    	printf("Could not create JSON object: Env array object NTS_IP\n");
		return NULL;
	}
    cJSON_AddItemToArray(env_variables_array, env_var_obj);

    sprintf(environment_var, "NETCONF_BASE=%d", base_netconf_port);
    cJSON *env_var_obj_2 = cJSON_CreateString(environment_var);
    if (env_var_obj_2 == NULL)
	{
    	printf("Could not create JSON object: Env array object NETCONF_BASE\n");
		return NULL;
	}
    cJSON_AddItemToArray(env_variables_array, env_var_obj_2);

	char scripts_dir[200];
	sprintf(scripts_dir, "SCRIPTS_DIR=%s", getenv("SCRIPTS_DIR"));
	cJSON *env_var_obj_3 = cJSON_CreateString(scripts_dir);
	if (env_var_obj_3 == NULL)
	{
		printf("Could not create JSON object: Env array object SCRIPTS_DIR\n");
		return NULL;
	}
	cJSON_AddItemToArray(env_variables_array, env_var_obj_3);

    cJSON_AddItemToObject(hostConfig, "Binds", binds);

    char *post_data_string = NULL;

    post_data_string = cJSON_PrintUnformatted(postDataJson);

    printf("Post data JSON:\n%s\n", post_data_string);

    if (postDataJson != NULL)
    {
    	cJSON_Delete(postDataJson);
    }

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data_string);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		return NULL;
	}
	else
	{
		cJSON *json_response = cJSON_Parse(curl_response_mem.memory);
		const cJSON *container_id = NULL;

		printf("%lu bytes retrieved\n", (unsigned long)curl_response_mem.size);

		container_id = cJSON_GetObjectItemCaseSensitive(json_response, "Id");

		if (cJSON_IsString(container_id) && (container_id->valuestring != NULL))
		{
			printf("Container id: \"%s\"\n", container_id->valuestring);

			char container_id_short[13];

			memset(container_id_short, '\0', sizeof(container_id_short));
			strncpy(container_id_short, container_id->valuestring, 12);

			printf("Container id short: \"%s\"\n", container_id_short);

		    cJSON_Delete(json_response);
			return strdup(container_id_short);
		}

	    cJSON_Delete(json_response);
	}

	return NULL;
}

static int start_docker_container_curl(char *container_id)
{
	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	CURLcode res;

	curl_easy_reset(curl);
	set_curl_common_info();

	char url[100];
	sprintf(url, "http:/v%s/containers/%s/start", getenv("DOCKER_ENGINE_VERSION"), container_id);

	curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		return SR_ERR_OPERATION_FAILED;
	}
	else
	{
		printf("Container %s started successfully!\n", container_id);
	}

	return SR_ERR_OK;
}

static int kill_and_remove_docker_container_curl(char *container_id)
{
	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	CURLcode res;

	curl_easy_reset(curl);
	set_curl_common_info();

	char url[100];
	sprintf(url, "http:/v%s/containers/%s?force=true", getenv("DOCKER_ENGINE_VERSION"), container_id);

	curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		return SR_ERR_OPERATION_FAILED;
	}
	else
	{
		printf("Container %s removed successfully!\n", container_id);
	}

	return SR_ERR_OK;
}

static int send_mount_device_instance_ssh(char *url, char *credentials, char *device_name, int device_port)
{
	CURLcode res;

	curl_easy_reset(curl_odl);
	set_curl_common_info_odl();

	char url_for_curl[200];
	sprintf(url_for_curl, "%s%s_%d", url, device_name, device_port);

	curl_easy_setopt(curl_odl, CURLOPT_URL, url_for_curl);

	char post_data_xml[1500];

	sprintf(post_data_xml,
			"<node xmlns=\"urn:TBD:params:xml:ns:yang:network-topology\">"
			"<node-id>%s_%d</node-id>"
			"<host xmlns=\"urn:opendaylight:netconf-node-topology\">%s</host>"
			"<port xmlns=\"urn:opendaylight:netconf-node-topology\">%d</port>"
			"<username xmlns=\"urn:opendaylight:netconf-node-topology\">%s</username>"
			"<password xmlns=\"urn:opendaylight:netconf-node-topology\">%s</password>"
			"<tcp-only xmlns=\"urn:opendaylight:netconf-node-topology\">false</tcp-only>"
			"<keepalive-delay xmlns=\"urn:opendaylight:netconf-node-topology\">120</keepalive-delay>"
			"<reconnect-on-changed-schema xmlns=\"urn:opendaylight:netconf-node-topology\">false</reconnect-on-changed-schema>"
			"<sleep-factor xmlns=\"urn:opendaylight:netconf-node-topology\">1.5</sleep-factor>"
			"<connection-timeout-millis xmlns=\"urn:opendaylight:netconf-node-topology\">20000</connection-timeout-millis>"
			"<max-connection-attempts xmlns=\"urn:opendaylight:netconf-node-topology\">100</max-connection-attempts>"
			"<between-attempts-timeout-millis xmlns=\"urn:opendaylight:netconf-node-topology\">2000</between-attempts-timeout-millis>"
			"</node>",
			device_name, device_port, getenv("NTS_IP"), device_port, "netconf", "netconf");

	printf("Post data:\n%s\n", post_data_xml);

	curl_easy_setopt(curl_odl, CURLOPT_POSTFIELDS, post_data_xml);
    curl_easy_setopt(curl_odl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl_odl, CURLOPT_USERPWD, credentials);

	res = curl_easy_perform(curl_odl);
	if (res != CURLE_OK)
	{
		printf("cURL failed to url=%s\n", url_for_curl);
	}

	long http_response_code = 0;
	curl_easy_getinfo (curl_odl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code >= 200 && http_response_code <= 226 && http_response_code != CURLE_ABORTED_BY_CALLBACK)
	{
		printf("cURL succeeded to url=%s\n", url_for_curl);
	}
	else
	{
	    printf("cURL to url=%s failed with code=%ld\n", url_for_curl, http_response_code);
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

static int send_mount_device_instance_tls(char *url, char *credentials, char *device_name, int device_port)
{
	CURLcode res;

	curl_easy_reset(curl_odl);
	set_curl_common_info_odl();

	char url_for_curl[200];
	sprintf(url_for_curl, "%s%s_%d", url, device_name, device_port);

	curl_easy_setopt(curl_odl, CURLOPT_URL, url_for_curl);

	char post_data_xml[1500];

	sprintf(post_data_xml,
			"<node xmlns=\"urn:TBD:params:xml:ns:yang:network-topology\">"
			"<protocol xmlns=\"urn:opendaylight:netconf-node-topology\">"
			"<name>TLS</name>"
			"</protocol>"
			"<node-id>%s_%d</node-id>"
			"<host xmlns=\"urn:opendaylight:netconf-node-topology\">%s</host>"
			"<key-based xmlns=\"urn:opendaylight:netconf-node-topology\">"
			"<username>%s</username>"
			"<key-id>device-key</key-id>"
			"</key-based>"
			"<port xmlns=\"urn:opendaylight:netconf-node-topology\">%d</port>"
			"<tcp-only xmlns=\"urn:opendaylight:netconf-node-topology\">false</tcp-only>"
			"<keepalive-delay xmlns=\"urn:opendaylight:netconf-node-topology\">120</keepalive-delay>"
			"<reconnect-on-changed-schema xmlns=\"urn:opendaylight:netconf-node-topology\">false</reconnect-on-changed-schema>"
			"<sleep-factor xmlns=\"urn:opendaylight:netconf-node-topology\">1.5</sleep-factor>"
			"<connection-timeout-millis xmlns=\"urn:opendaylight:netconf-node-topology\">20000</connection-timeout-millis>"
			"<max-connection-attempts xmlns=\"urn:opendaylight:netconf-node-topology\">100</max-connection-attempts>"
			"<between-attempts-timeout-millis xmlns=\"urn:opendaylight:netconf-node-topology\">2000</between-attempts-timeout-millis>"
			"</node>",
			device_name, device_port, getenv("NTS_IP"), "netconf", device_port);

	printf("Post data:\n%s\n", post_data_xml);

	curl_easy_setopt(curl_odl, CURLOPT_POSTFIELDS, post_data_xml);
    curl_easy_setopt(curl_odl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl_odl, CURLOPT_USERPWD, credentials);

	res = curl_easy_perform(curl_odl);
	if (res != CURLE_OK)
	{
		printf("cURL failed to url=%s\n", url_for_curl);
	}

	long http_response_code = 0;
	curl_easy_getinfo (curl_odl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code >= 200 && http_response_code <= 226 && http_response_code != CURLE_ABORTED_BY_CALLBACK)
	{
		printf("cURL succeeded to url=%s\n", url_for_curl);
	}
	else
	{
	    printf("cURL to url=%s failed with code=%ld\n", url_for_curl, http_response_code);
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

static int send_unmount_device_instance(char *url, char *credentials, char *device_name, int device_port)
{
	CURLcode res;

	curl_easy_reset(curl_odl);
	set_curl_common_info_odl();

	char url_for_curl[200];
	sprintf(url_for_curl, "%s%s_%d", url, device_name, device_port);

	curl_easy_setopt(curl_odl, CURLOPT_URL, url_for_curl);

	curl_easy_setopt(curl_odl, CURLOPT_POSTFIELDS, "");
	curl_easy_setopt(curl_odl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl_odl, CURLOPT_USERPWD, credentials);

	res = curl_easy_perform(curl_odl);
	if (res != CURLE_OK)
	{
		printf("cURL failed to url=%s\n", url_for_curl);
	}

	long http_response_code = 0;
	curl_easy_getinfo (curl_odl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code == 200 && http_response_code != CURLE_ABORTED_BY_CALLBACK)
	{
		printf("cURL succeeded to url=%s\n", url_for_curl);
	}
	else
	{
		printf("cURL to url=%s failed with code=%ld\n", url_for_curl, http_response_code);
		return SR_ERR_OPERATION_FAILED;
	}


	return SR_ERR_OK;
}


static int send_mount_device(device_t *current_device, controller_t controller_details)
{
	int rc = SR_ERR_OK;
	bool is_mounted = true;

	//This is where we hardcoded: 7 devices will have SSH connections and 3 devices will have TLS connections
	for (int port = 0; port < NETCONF_CONNECTIONS_PER_DEVICE - 3; ++port)
	{
		rc = send_mount_device_instance_ssh(controller_details.url, controller_details.credentials,
				current_device->device_id, current_device->netconf_port + port);
		if (rc != SR_ERR_OK)
		{
			is_mounted = false;
		}
	}
	for (int port = NETCONF_CONNECTIONS_PER_DEVICE - 3; port < NETCONF_CONNECTIONS_PER_DEVICE; ++port)
	{
		rc = send_mount_device_instance_tls(controller_details.url, controller_details.credentials,
				current_device->device_id, current_device->netconf_port + port);
		if (rc != SR_ERR_OK)
		{
			is_mounted = false;
		}
	}

	current_device->is_mounted = is_mounted;

	return SR_ERR_OK;
}

static int send_unmount_device(device_t *current_device, controller_t controller_details)
{
	int rc = SR_ERR_OK;

	for (int port = 0; port < NETCONF_CONNECTIONS_PER_DEVICE; ++port)
	{
		rc = send_unmount_device_instance(controller_details.url, controller_details.credentials,
				current_device->device_id, current_device->netconf_port + port);
		if (rc != SR_ERR_OK)
		{
			printf("Could not send unmount for ODL with url=\"%s\", for device=\"%s\" and port=%d\n",
					controller_details.url, current_device->device_id, current_device->netconf_port);
		}
	}
	current_device->is_mounted = false;

	return SR_ERR_OK;
}

device_stack_t *new_device_stack(void)
{
	device_stack_t *stack = malloc(sizeof(*stack));

	if (stack) {
		stack->head = NULL;
		stack->stack_size = 0;
	}
	return stack;
}

void push_device(device_stack_t *theStack, char *dev_id, int port)
{
	device_t *new_dev = malloc(sizeof(*new_dev));

	if (new_dev) {
		new_dev->device_id = strdup(dev_id);
		new_dev->netconf_port = port;
		new_dev->is_mounted = false;
		new_dev->operational_state = strdup("not-specified");

		new_dev->next = theStack->head;

		theStack->head = new_dev;
		theStack->stack_size++;
	}
}

void pop_device(device_stack_t *theStack)
{
	if (theStack && theStack->head) {
		device_t *temp = theStack->head;
		theStack->head = theStack->head->next;

		free(temp->device_id);
		free(temp->operational_state);
		free(temp);
		theStack->stack_size--;
	}
}

int get_netconf_port_next(device_stack_t *theStack)
{
	if (theStack && theStack->stack_size > 0) {
		return theStack->head->netconf_port + NETCONF_CONNECTIONS_PER_DEVICE;
	}

	return get_netconf_port_base();
}

int get_netconf_port_base()
{
	int netconf_port_base = 0, rc;

	char *netconf_base_string = getenv("NETCONF_BASE");

	if (netconf_base_string != NULL)
	{
		rc = sscanf(netconf_base_string, "%d", &netconf_port_base);
		if (rc != 1)
		{
			printf("Could not get the NETCONF_BASE port! Using the default 30.000...\n");
			netconf_port_base = 30000;
		}
	}

	return netconf_port_base;
}


char *get_id_last_device(device_stack_t *theStack)
{
	if (theStack && theStack->head) {
		return theStack->head->device_id;
	}
	return NULL;
}

int get_current_number_of_mounted_devices(device_stack_t *theStack)
{
	int mounted_devices = 0;

	if (theStack && theStack->head)
	{
		device_t *current_device = theStack->head;

		while (current_device != NULL)
		{
			if (current_device->is_mounted)
			{
				mounted_devices++;
			}
			current_device = current_device->next;
		}
	}

	return mounted_devices;
}

int get_current_number_of_devices(device_stack_t *theStack)
{
	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	CURLcode res;

	curl_easy_reset(curl);
	set_curl_common_info();

	char url[100];
	sprintf(url, "http:/v%s/containers/json?all=true&filters={\"label\":[\"NTS\"],\"status\":[\"running\"]}",
			getenv("DOCKER_ENGINE_VERSION"));

	curl_easy_setopt(curl, CURLOPT_URL, url);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		return SR_ERR_OPERATION_FAILED;
	}
	else
	{
		cJSON *json_response = cJSON_Parse(curl_response_mem.memory);

		printf("%lu bytes retrieved\n", (unsigned long)curl_response_mem.size);

		if (json_response == NULL || !cJSON_IsArray(json_response))
		{
			printf("Could not parse JSON response for url=\"%s\"\n", url);
			return SR_ERR_OPERATION_FAILED;
		}

		int num_of_devices = cJSON_GetArraySize(json_response);
		cJSON_Delete(json_response);

		return num_of_devices;
	}

	return 0;
}

static int set_operational_state_of_device(device_stack_t *theStack, char *device_id, char *operational_state)
{
	if (theStack && theStack->head)
	{
		device_t *current_device = theStack->head;

		while (current_device != NULL)
		{
			if (strcmp(current_device->device_id, device_id) == 0)
			{
				free(current_device->operational_state);
				current_device->operational_state = strdup(operational_state);

				return SR_ERR_OK;
			}

			current_device = current_device->next;
		}
	}

	printf("Could not find device with uuid=\"%s\"\n", device_id);
	return SR_ERR_OPERATION_FAILED;
}

char* get_docker_container_operational_state(device_stack_t *theStack, char *container_id)
{
	if (theStack && theStack->head)
	{
		device_t *current_device = theStack->head;

		while (current_device != NULL)
		{
			if (strcmp(current_device->device_id, container_id) == 0)
			{
				return current_device->operational_state;
			}

			current_device = current_device->next;
		}
	}

	return NULL;
}

int start_device(device_stack_t *theStack)
{
	int rc = SR_ERR_OK;
	static cJSON* managerBindings = NULL;

	if (managerBindings == NULL)
	{
		managerBindings = get_docker_container_bindings();
	}

	int netconf_base = get_netconf_port_next(theStack);

	char *dev_id = create_docker_container_curl(netconf_base, managerBindings);

	push_device(theStack, dev_id, netconf_base);

	rc = start_docker_container_curl(dev_id);
	if (rc != SR_ERR_OK)
	{
		printf("Could not start device with device_id=\"%s\"\n", dev_id);
	}

	if (dev_id) {
		free(dev_id);
	}

	return SR_ERR_OK;
}

int _init_curl()
{
	curl = curl_easy_init();

	if (curl == NULL) {
		printf("cURL initialization error! Aborting call!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

int cleanup_curl()
{
	if (curl != NULL)
	{
		curl_easy_cleanup(curl);
	}

	return SR_ERR_OK;
}

int _init_curl_odl()
{
	curl_odl = curl_easy_init();

	if (curl_odl == NULL) {
		printf("cURL initialization error! Aborting call!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

int cleanup_curl_odl()
{
	if (curl_odl != NULL)
	{
		curl_easy_cleanup(curl_odl);
	}

	return SR_ERR_OK;
}

int stop_device(device_stack_t *theStack)
{
	int rc = SR_ERR_OK;
	char *last_id = get_id_last_device(theStack);

	rc = kill_and_remove_docker_container_curl(last_id);
	if (rc != SR_ERR_OK)
	{
		printf("Could not kill and remove docker container with uuid=\"%s\"\n", last_id);
	}

	pop_device(theStack);

	return SR_ERR_OK;
}

int mount_device(device_stack_t *theStack, controller_t controller_details)
{
	int rc;

	if (theStack && theStack->head)
	{
		device_t *current_device = theStack->head;
		while (current_device != NULL && current_device->is_mounted == true)
		{
			printf("Device \"%s\" is already mounted, skipping...\n", current_device->device_id);
			current_device = current_device->next;
		}

		if (current_device != NULL)
		{
			printf("Sending mount device for device \"%s\"...\n", current_device->device_id);
			rc = send_mount_device(current_device, controller_details);
			if (rc != SR_ERR_OK)
			{
				return SR_ERR_OPERATION_FAILED;
			}
		}
	}

	return SR_ERR_OK;
}

int unmount_device(device_stack_t *theStack, controller_t controller_list)
{
	int rc;

	if (theStack && theStack->head)
	{
		device_t *current_device = theStack->head;
		while (current_device != NULL && current_device->is_mounted == false)
		{
			printf("Device \"%s\" is already unmounted, skipping...\n", current_device->device_id);
			current_device = current_device->next;
		}

		if (current_device != NULL)
		{
			printf("Sending unmount device for device \"%s\"...\n", current_device->device_id);
			rc = send_unmount_device(current_device, controller_list);
			if (rc != SR_ERR_OK)
			{
				return SR_ERR_OPERATION_FAILED;
			}
		}
	}

	return SR_ERR_OK;
}

int get_docker_containers_operational_state_curl(device_stack_t *theStack)
{
	int rc = SR_ERR_OK;
	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	CURLcode res;

	curl_easy_reset(curl);
	set_curl_common_info();

	char url[100];
	sprintf(url, "http:/v%s/containers/json?all=true&filters={\"label\":[\"NTS\"]}", getenv("DOCKER_ENGINE_VERSION"));

	curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		return SR_ERR_OPERATION_FAILED;
	}
	else
	{
		cJSON *json_response = cJSON_Parse(curl_response_mem.memory);
		const cJSON *container = NULL;

		printf("%lu bytes retrieved\n", (unsigned long)curl_response_mem.size);

		if (json_response == NULL || !cJSON_IsArray(json_response))
		{
			printf("Could not parse JSON response for url=\"%s\"\n", url);
			return SR_ERR_OPERATION_FAILED;
		}

	    cJSON_ArrayForEach(container, json_response)
	    {
	        cJSON *container_id_long = cJSON_GetObjectItemCaseSensitive(container, "Id");
	        cJSON *state = cJSON_GetObjectItemCaseSensitive(container, "State");

			if (cJSON_IsString(container_id_long) && (container_id_long->valuestring != NULL))
			{
				char container_id_short[13];

				memset(container_id_short, '\0', sizeof(container_id_short));
				strncpy(container_id_short, container_id_long->valuestring, 12);

				if (cJSON_IsString(state) && (state->valuestring != NULL))
				{
					rc = set_operational_state_of_device(theStack, container_id_short, state->valuestring);
					if (rc != SR_ERR_OK)
					{
						printf("Could not set the operational state for the device with uuid=\"%s\"\n", container_id_short);
					}
				}
			}
	    }

	    cJSON_Delete(json_response);
	}

	return SR_ERR_OK;
}

char* get_docker_container_resource_stats(device_stack_t *theStack)
{
	char line[LINE_BUFSIZE];
	int linenr;
	FILE *pipe;

	/* Get a pipe where the output from the scripts comes in */
	char script[200];
	sprintf(script, "%s/docker_stats.sh", getenv("SCRIPTS_DIR"));

	pipe = popen(script, "r");
	if (pipe == NULL) {  /* check for errors */
		printf("Could not open script.\n");
		return NULL;        /* return with exit code indicating error */
	}

	/* Read script output from the pipe line by line */
	linenr = 1;
	while (fgets(line, LINE_BUFSIZE, pipe) != NULL) {
		printf("Script output line %d: %s", linenr, line);
		++linenr;

		pclose(pipe); /* Close the pipe */
		return strdup(line);
	}

	/* Once here, out of the loop, the script has ended. */
	pclose(pipe); /* Close the pipe */
	return NULL;     /* return with exit code indicating success. */
}

int notification_delay_period_changed(int period)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *notifConfig = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifConfig))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *faultNotifDelay = cJSON_GetObjectItemCaseSensitive(notifConfig, "fault-notification-delay-period");
	if (!cJSON_IsNumber(faultNotifDelay))
	{
		printf("Configuration JSON is not as expected: fault-notification-delay-period is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the fault-notification-delay-period object
	cJSON_SetNumberValue(faultNotifDelay, period);

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}

int ves_heartbeat_period_changed(int period)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *notifConfig = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifConfig))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesHeartbeatPeriod = cJSON_GetObjectItemCaseSensitive(notifConfig, "ves-heartbeat-period");
	if (!cJSON_IsNumber(vesHeartbeatPeriod))
	{
		printf("Configuration JSON is not as expected: ves-heartbeat-period is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the fault-notification-delay-period object
	cJSON_SetNumberValue(vesHeartbeatPeriod, period);

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}

static int add_keystore_entry_odl(char *url, char *credentials)
{
	CURLcode res;

	curl_easy_reset(curl_odl);
	set_curl_common_info_odl();

	char url_for_curl[200];
	sprintf(url_for_curl, "%s", url);

	curl_easy_setopt(curl_odl, CURLOPT_URL, url_for_curl);

	char post_data_xml[2000];

	sprintf(post_data_xml,
			"<input xmlns=\"urn:opendaylight:netconf:keystore\">"
			"<key-credential>"
			"<key-id>device-key</key-id>"
			"<private-key>MIIEpAIBAAKCAQEAueCQaNQWoNmFK6LKu1p8U8ZWdWg/PvDdLsJyzfzl/Qw4UA68"
			"SfFNaY06zZl8QB9W02nr5kWeeMY0VA3adrPgOlvfx3oWlFbkETnMaN4OT3WTQ0Wt"
			"6jAWZDzVfopwpJPAzRPxACDftIqFGagYcF32hZlVNqqnVdbXh0S0EViweqp/dbG4"
			"VDUHSNVbglc+u4UbEzNIFXMdEFsJZpkynOmSiTsIATqIhb+2srkVgLwhfkC2qkuH"
			"QwAHdubuB07ObM2z01UhyEdDvEYGHwtYAGDBL2TAcsI0oGeVkRyuOkV0QY0UN7UE"
			"FI1yTYw+xZ42HgFx3uGwApCImxhbj69GBYWFqwIDAQABAoIBAQCZN9kR8DGu6V7y"
			"t0Ax68asL8O5B/OKaHWKQ9LqpVrXmikZJOxkbzoGldow/CIFoU+q+Zbwu9aDa65a"
			"0wiP7Hoa4Py3q5XNNUrOQDyU/OYC7cI0I83WS0lJ2zOJGYj8wKae5Z81IeQFKGHK"
			"4lsy1OGPAvPRGh7RjUUgRavA2MCwe07rWRuDb/OJFe4Oh56UMEjwMiNBtMNtncog"
			"j1vr/qgRJdf9tf0zlJmLvUJ9+HSFFV9I/97LJyFhb95gAfHkjdVroLVgT3Cho+4P"
			"WtZaKCIGD0OwfOG2nLV4leXvRUk62/LMlB8NI9+JF7Xm+HCKbaWHNWC7mvWSLV58"
			"Zl4AbUWRAoGBANyJ6SFHFRHSPDY026SsdMzXR0eUxBAK7G70oSBKKhY+O1j0ocLE"
			"jI2krHJBhHbLlnvJVyMUaCUOTS5m0uDw9hgSsAqeSL3hL38kxVZw+KNG9Ouno1Fl"
			"KnE/xXHlPQyeGs/P8nAMzHZxQtEsQdQayJEhK2XXHTsy7Q3MxDisfVJ1AoGBANfD"
			"34gB+OMx6pwj7zk3qWbYXSX8xjCZMR0ciko+h4xeMP2N8B0oyoqC+v1ABMAtJ3wG"
			"sGZd0hV9gwM7OUM3SEwkn6oeg1GemWLcn4rlSmTnZc4aeVwrEWlnSNFX3s4g9l4u"
			"k8Ugu4MVJYqH8HuDQ5Ggl6/QAwPzMSEdCW0O+jOfAoGAIBRbegC5+t6m7Yegz4Ja"
			"dxV1g98K6f58x+MDsQu4tYWV4mmrQgaPH2dtwizvlMwmdpkh+LNWNtWuumowkJHc"
			"akIFo3XExQIFg6wYnGtQb4e5xrGa2xMpKlIJaXjb+YLiCYqJDG2ALFZrTrvuU2kV"
			"9a5qfqTc1qigvNolTM0iaaUCgYApmrZWhnLUdEKV2wP813PNxfioI4afxlpHD8LG"
			"sCn48gymR6E+Lihn7vuwq5B+8fYEH1ISWxLwW+RQUjIneNhy/jjfV8TgjyFqg7or"
			"0Sy4KjpiNI6kLBXOakELRNNMkeSPopGR2E7v5rr3bGD9oAD+aqX1G7oJH/KgPPYd"
			"Vl7+ZwKBgQDcHyWYrimjyUgKaQD2GmoO9wdcJYQ59ke9K+OuGlp4ti5arsi7N1tP"
			"B4f09aeELM2ASIuk8Q/Mx0jQFnm8lzRFXdewgvdPoZW/7VufM9O7dGPOc41cm2Dh"
			"yrTcXx/VmUBb+/fnXVEgCv7gylp/wtdTGHQBQJHR81jFBz0lnLj+gg==</private-key>"
			"<passphrase></passphrase>"
			"</key-credential>"
			"</input>");

	printf("Post data:\n%s\n", post_data_xml);

	curl_easy_setopt(curl_odl, CURLOPT_POSTFIELDS, post_data_xml);
	curl_easy_setopt(curl_odl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl_odl, CURLOPT_USERPWD, credentials);

	res = curl_easy_perform(curl_odl);
	if (res != CURLE_OK)
	{
		printf("cURL failed to url=%s\n", url_for_curl);
	}

	long http_response_code = 0;
	curl_easy_getinfo (curl_odl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code >= 200 && http_response_code <= 226 && http_response_code != CURLE_ABORTED_BY_CALLBACK)
	{
		printf("cURL succeeded to url=%s\n", url_for_curl);
	}
	else
	{
		printf("cURL to url=%s failed with code=%ld\n", url_for_curl, http_response_code);
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

static int add_private_key_odl(char *url, char *credentials)
{
	CURLcode res;

	curl_easy_reset(curl_odl);
	set_curl_common_info_odl();

	char url_for_curl[200];
	sprintf(url_for_curl, "%s", url);

	curl_easy_setopt(curl_odl, CURLOPT_URL, url_for_curl);

	char post_data_xml[4000];

	sprintf(post_data_xml,
			"<input xmlns=\"urn:opendaylight:netconf:keystore\">"
			"<private-key>"
			"<name>device-key</name>"
			"<data>MIIEpAIBAAKCAQEAueCQaNQWoNmFK6LKu1p8U8ZWdWg/PvDdLsJyzfzl/Qw4UA68SfFNaY06zZl8QB9W02nr5kWeeMY0VA3adrPgOlvfx3oWlFbkETnMaN4OT3WTQ0Wt6jAWZDzVfopwpJPAzRPxACDftIqFGagYcF32hZlVNqqnVdbXh0S0EViweqp/dbG4VDUHSNVbglc+u4UbEzNIFXMdEFsJZpkynOmSiTsIATqIhb+2srkVgLwhfkC2qkuHQwAHdubuB07ObM2z01UhyEdDvEYGHwtYAGDBL2TAcsI0oGeVkRyuOkV0QY0UN7UEFI1yTYw+xZ42HgFx3uGwApCImxhbj69GBYWFqwIDAQABAoIBAQCZN9kR8DGu6V7yt0Ax68asL8O5B/OKaHWKQ9LqpVrXmikZJOxkbzoGldow/CIFoU+q+Zbwu9aDa65a0wiP7Hoa4Py3q5XNNUrOQDyU/OYC7cI0I83WS0lJ2zOJGYj8wKae5Z81IeQFKGHK4lsy1OGPAvPRGh7RjUUgRavA2MCwe07rWRuDb/OJFe4Oh56UMEjwMiNBtMNtncogj1vr/qgRJdf9tf0zlJmLvUJ9+HSFFV9I/97LJyFhb95gAfHkjdVroLVgT3Cho+4PWtZaKCIGD0OwfOG2nLV4leXvRUk62/LMlB8NI9+JF7Xm+HCKbaWHNWC7mvWSLV58Zl4AbUWRAoGBANyJ6SFHFRHSPDY026SsdMzXR0eUxBAK7G70oSBKKhY+O1j0ocLEjI2krHJBhHbLlnvJVyMUaCUOTS5m0uDw9hgSsAqeSL3hL38kxVZw+KNG9Ouno1FlKnE/xXHlPQyeGs/P8nAMzHZxQtEsQdQayJEhK2XXHTsy7Q3MxDisfVJ1AoGBANfD34gB+OMx6pwj7zk3qWbYXSX8xjCZMR0ciko+h4xeMP2N8B0oyoqC+v1ABMAtJ3wGsGZd0hV9gwM7OUM3SEwkn6oeg1GemWLcn4rlSmTnZc4aeVwrEWlnSNFX3s4g9l4uk8Ugu4MVJYqH8HuDQ5Ggl6/QAwPzMSEdCW0O+jOfAoGAIBRbegC5+t6m7Yegz4JadxV1g98K6f58x+MDsQu4tYWV4mmrQgaPH2dtwizvlMwmdpkh+LNWNtWuumowkJHcakIFo3XExQIFg6wYnGtQb4e5xrGa2xMpKlIJaXjb+YLiCYqJDG2ALFZrTrvuU2kV9a5qfqTc1qigvNolTM0iaaUCgYApmrZWhnLUdEKV2wP813PNxfioI4afxlpHD8LGsCn48gymR6E+Lihn7vuwq5B+8fYEH1ISWxLwW+RQUjIneNhy/jjfV8TgjyFqg7or0Sy4KjpiNI6kLBXOakELRNNMkeSPopGR2E7v5rr3bGD9oAD+aqX1G7oJH/KgPPYdVl7+ZwKBgQDcHyWYrimjyUgKaQD2GmoO9wdcJYQ59ke9K+OuGlp4ti5arsi7N1tPB4f09aeELM2ASIuk8Q/Mx0jQFnm8lzRFXdewgvdPoZW/7VufM9O7dGPOc41cm2DhyrTcXx/VmUBb+/fnXVEgCv7gylp/wtdTGHQBQJHR81jFBz0lnLj+gg==</data>"
			"<certificate-chain>MIIECTCCAvGgAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCQ1oxFjAUBgNVBAgMDVNvdXRoIE1vcmF2aWExDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMRMwEQYDVQQDDApleGFtcGxlIENBMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlY2FAbG9jYWxob3N0MB4XDTE1MDczMDA3MjcxOFoXDTM1MDcyNTA3MjcxOFowgYUxCzAJBgNVBAYTAkNaMRYwFAYDVQQIDA1Tb3V0aCBNb3JhdmlhMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzEXMBUGA1UEAwwOZXhhbXBsZSBjbGllbnQxJjAkBgkqhkiG9w0BCQEWF2V4YW1wbGVjbGllbnRAbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueCQaNQWoNmFK6LKu1p8U8ZWdWg/PvDdLsJyzfzl/Qw4UA68SfFNaY06zZl8QB9W02nr5kWeeMY0VA3adrPgOlvfx3oWlFbkETnMaN4OT3WTQ0Wt6jAWZDzVfopwpJPAzRPxACDftIqFGagYcF32hZlVNqqnVdbXh0S0EViweqp/dbG4VDUHSNVbglc+u4UbEzNIFXMdEFsJZpkynOmSiTsIATqIhb+2srkVgLwhfkC2qkuHQwAHdubuB07ObM2z01UhyEdDvEYGHwtYAGDBL2TAcsI0oGeVkRyuOkV0QY0UN7UEFI1yTYw+xZ42HgFx3uGwApCImxhbj69GBYWFqwIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUXGpLeLnh2cSDARAVA7KrBxGYpo8wHwYDVR0jBBgwFoAUc1YQIqjZsHVwlea0AB4N+ilNI2gwDQYJKoZIhvcNAQELBQADggEBAJPV3RTXFRtNyOU4rjPpYeBAIAFp2aqGc4t2J1c7oPp/1n+lZvjnwtlJpZHxMM783e2ryDQ6dkvXDf8kpwKlg3U3mkJ3xKkDdWrM4QwghXdCN519aa9qmu0zdFL+jUAaWlQ5tsceOrvbusCcbMqiFGk/QfpHqPv52SVWbYyUx7IX7DE+UjgsLHycfV/tlcx4ZE6soTzl9VdgSL/zmzG3rjsr58J80rXckLgBhvijgBlIAJvWfC7D0vaouvBInSFXymdPVoUDZ30cdGLf+hI/i/TfsEMOinLrXVdkSGNo6FXAHKSvXeB9oFKSzhQ7OPyRyqvEPycUSw/qD6FVr80oDDc=</certificate-chain>"
			"</private-key>"
			"</input>");

	printf("Post data:\n%s\n", post_data_xml);

	curl_easy_setopt(curl_odl, CURLOPT_POSTFIELDS, post_data_xml);
	curl_easy_setopt(curl_odl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl_odl, CURLOPT_USERPWD, credentials);

	res = curl_easy_perform(curl_odl);
	if (res != CURLE_OK)
	{
		printf("cURL failed to url=%s\n", url_for_curl);
	}

	long http_response_code = 0;
	curl_easy_getinfo (curl_odl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code >= 200 && http_response_code <= 226 && http_response_code != CURLE_ABORTED_BY_CALLBACK)
	{
		printf("cURL succeeded to url=%s\n", url_for_curl);
	}
	else
	{
		printf("cURL to url=%s failed with code=%ld\n", url_for_curl, http_response_code);
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

static int add_trusted_ca_odl(char *url, char *credentials)
{
	CURLcode res;

	curl_easy_reset(curl_odl);
	set_curl_common_info_odl();

	char url_for_curl[200];
	sprintf(url_for_curl, "%s", url);

	curl_easy_setopt(curl_odl, CURLOPT_URL, url_for_curl);

	char post_data_xml[2000];

	sprintf(post_data_xml,
			"<input xmlns=\"urn:opendaylight:netconf:keystore\">"
			"<trusted-certificate>"
			"<name>test_trusted_cert</name>"
			"<certificate>MIID7TCCAtWgAwIBAgIJAMtE1NGAR5KoMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJDWjEWMBQGA1UECAwNU291dGggTW9yYXZpYTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEzARBgNVBAMMCmV4YW1wbGUgQ0ExIjAgBgkqhkiG9w0BCQEWE2V4YW1wbGVjYUBsb2NhbGhvc3QwHhcNMTQwNzI0MTQxOTAyWhcNMjQwNzIxMTQxOTAyWjCBjDELMAkGA1UEBhMCQ1oxFjAUBgNVBAgMDVNvdXRoIE1vcmF2aWExDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMRMwEQYDVQQDDApleGFtcGxlIENBMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlY2FAbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArD3TDHPAMT2Z84orK4lMlarbgooIUCcRZyLe+QM+8KY8Hn+mGaxPEOTSL3ywszqefB/Utm2hPKLHX684iRC14ID9WDGHxPjvoPArhgFhfV+qnPfxKTgxZC12uOj4u1V9y+SkTCocFbRfXVBGpojrBuDHXkDMDEWNvr8/52YCv7bGaiBwUHolcLCUbmtKILCG0RNJyTaJpXQdAeq5Z1SJotpbfYFFtAXB32hVoLug1dzl2tjG9sb1wq3QaDExcbC5w6P65qOkNoyym9ne6QlQagCqVDyFn3vcqkRaTjvZmxauCeUxXgJoXkyWcm0lM1KMHdoTArmchw2Dz0yHHSyDAQIDAQABo1AwTjAdBgNVHQ4EFgQUc1YQIqjZsHVwlea0AB4N+ilNI2gwHwYDVR0jBBgwFoAUc1YQIqjZsHVwlea0AB4N+ilNI2gwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAI/1KH60qnw9Xs2RGfi0/IKf5EynXt4bQX8EIyVKwSkYKe04zZxYfLIl/Q2HOPYoFmm3daj5ddr0ZS1i4p4fTUhstjsYWvXs3W/HhVmFUslakkn3PrswhP77fCk6eEJLxdfyJ1C7Uudq2m1isZbKih+XF0mG1LxJaDMocSz4eAya7M5brwjy8DoOmA1TnLQFCVcpn+sCr7VC4wE/JqxyVhBCk/MuGqqM3B1j90bGFZ112ZOecyE0EDSr6IbiRBtmeNbEwOFjKXhNLYdxpBZ9D8A/368OckZkCrVLGuJNxK9UwCVTe8IhotHUqU9EqFDmxdV8oIdU/OzUwwNPA/Bd/9g==</certificate>"
			"</trusted-certificate>"
			"</input>");

	printf("Post data:\n%s\n", post_data_xml);

	curl_easy_setopt(curl_odl, CURLOPT_POSTFIELDS, post_data_xml);
	curl_easy_setopt(curl_odl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl_odl, CURLOPT_USERPWD, credentials);

	res = curl_easy_perform(curl_odl);
	if (res != CURLE_OK)
	{
		printf("cURL failed to url=%s\n", url_for_curl);
	}

	long http_response_code = 0;
	curl_easy_getinfo (curl_odl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code >= 200 && http_response_code <= 226 && http_response_code != CURLE_ABORTED_BY_CALLBACK)
	{
		printf("cURL succeeded to url=%s\n", url_for_curl);
	}
	else
	{
		printf("cURL to url=%s failed with code=%ld\n", url_for_curl, http_response_code);
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

int add_key_pair_to_odl(controller_t *controller_list, int controller_list_size)
{
	int rc = SR_ERR_OK;

	rc = add_keystore_entry_odl(controller_list[0].url_for_keystore_add, controller_list[0].credentials);
	if (rc != SR_ERR_OK)
	{
		printf("Failed to add keystore entry to ODL.\n");
	}

	rc = add_private_key_odl(controller_list[0].url_for_private_key_add, controller_list[0].credentials);
	if (rc != SR_ERR_OK)
	{
		printf("Failed to add private key entry to ODL.\n");
	}

	rc = add_trusted_ca_odl(controller_list[0].url_for_trusted_ca_add, controller_list[0].credentials);
	if (rc != SR_ERR_OK)
	{
		printf("Failed to add trusted CA entry to ODL.\n");
	}

	return SR_ERR_OK;
}

int ves_ip_changed(char *new_ip)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesIp = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-ip");
	if (!cJSON_IsString(vesIp))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-ip is not a string");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the fault-notification-delay-period object
	cJSON_ReplaceItemInObject(vesDetails, "ves-endpoint-ip", cJSON_CreateString(new_ip));

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}

int ves_port_changed(int new_port)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesPort = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-port");
	if (!cJSON_IsNumber(vesPort))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-port is not a number.");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the fault-notification-delay-period object
	cJSON_SetNumberValue(vesPort, new_port);

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}

int ves_registration_changed(cJSON_bool new_bool)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesRegistration = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-registration");
	if (!cJSON_IsBool(vesRegistration))
	{
		printf("Configuration JSON is not as expected: ves-registration is not a bool.");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the ves-registration object
	cJSON_ReplaceItemInObject(vesDetails, "ves-registration", cJSON_CreateBool(new_bool));

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}

int is_netconf_available_changed(cJSON_bool new_bool)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *notifConfig = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifConfig))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *isNetconfAvailable = cJSON_GetObjectItemCaseSensitive(notifConfig, "is-netconf-available");
	if (!cJSON_IsBool(isNetconfAvailable))
	{
		printf("Configuration JSON is not as expected: is-netconf-available is not a bool.");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the ves-registration object
	cJSON_ReplaceItemInObject(notifConfig, "is-netconf-available", cJSON_CreateBool(new_bool));

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}

int is_ves_available_changed(cJSON_bool new_bool)
{
	char *stringConfiguration = readConfigFileInString();

	if (stringConfiguration == NULL)
	{
		printf("Could not read configuration file!\n");
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfiguration);
	if (jsonConfig == NULL)
	{
		free(stringConfiguration);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfiguration);
	stringConfiguration = NULL;

	cJSON *notifConfig = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifConfig))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *isVesAvailable = cJSON_GetObjectItemCaseSensitive(notifConfig, "is-ves-available");
	if (!cJSON_IsBool(isVesAvailable))
	{
		printf("Configuration JSON is not as expected: is-ves-available is not a bool.");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	//we set the value of the ves-registration object
	cJSON_ReplaceItemInObject(notifConfig, "is-ves-available", cJSON_CreateBool(new_bool));

	//writing the new JSON to the configuration file
	stringConfiguration = cJSON_Print(jsonConfig);
	writeConfigFile(stringConfiguration);

	free(jsonConfig);

	return SR_ERR_OK;
}
