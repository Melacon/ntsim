/*
 * heartbeat.c
 *
 *  Created on: Oct 24, 2019
 *      Author: parallels
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>

#include <pthread.h>

#include "heartbeat.h"
#include "sysrepo.h"
#include "sysrepo/values.h"

#include "utils.h"

#define LINE_BUFSIZE 128
#define SLEEP_BEFORE_PNF_AUTOREG 60

volatile int exit_application = 0;

pthread_mutex_t lock;

static 	CURL *curl;

static void set_curl_common_info()
{
	struct curl_slist *chunk = NULL;
	chunk = curl_slist_append(chunk, "Content-Type: application/json");
	chunk = curl_slist_append(chunk, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L); // seconds timeout for a connection
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); //seconds timeout for an operation

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
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

static void prepare_ves_message_curl(void)
{
	curl_easy_reset(curl);
	set_curl_common_info();

	char *ves_ip = getVesIpFromConfigJson();
	int ves_port = getVesPortFromConfigJson();

	char url[100];
	sprintf(url, "http://%s:%d/eventListener/v7", ves_ip, ves_port);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	free(ves_ip);

//	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

	return;
}
/*
 * Heartbeat payload example
 *
 * {
  "event": {
    "commonEventHeader": {
      "domain": "heartbeat",
      "eventId": "parallels-Parallels-Virtual-Platform_2019-10-24T10:25:25.514Z",
      "eventName": "heartbeat_Controller",
      "eventType": "Controller",
      "sequence": 0,
      "priority": "Low",
      "reportingEntityId": "",
      "reportingEntityName": "parallels-Parallels-Virtual-Platform",
      "sourceId": "",
      "sourceName": "parallels-Parallels-Virtual-Platform",
      "startEpochMicrosec": 1571912725514,
      "lastEpochMicrosec": 1571912725514,
      "nfNamingCode": "sdn controller",
      "nfVendorName": "sdn",
      "timeZoneOffset": "+00:00",
      "version": "4.0.1",
      "vesEventListenerVersion":"7.0.1"
    },
    "heartbeatFields": {
      "heartbeatFieldsVersion": "3.0",
      "heartbeatInterval": 20,
      "additionalFields": {
        "eventTime": "2019-10-24T10:25:25.514Z"
      }
    }
  }
}
*
* */

static int send_heartbeat(int heartbeat_interval)
{
	CURLcode res;

	prepare_ves_message_curl();

	cJSON *postDataJson = cJSON_CreateObject();

	cJSON *event = cJSON_CreateObject();
	if (event == NULL)
	{
		printf("Could not create JSON object: event\n");
		return 1;
	}
	cJSON_AddItemToObject(postDataJson, "event", event);

	char hostname[100];
	sprintf(hostname, "%s", getenv("HOSTNAME"));

	cJSON *commonEventHeader = vesCreateCommonEventHeader("heartbeat", "Controller", hostname);
	if (commonEventHeader == NULL)
	{
		printf("Could not create JSON object: commonEventHeader\n");
		return 1;
	}
	cJSON_AddItemToObject(event, "commonEventHeader", commonEventHeader);

	cJSON *heartbeatFields = vesCreateHeartbeatFields(heartbeat_interval);
	if (heartbeatFields == NULL)
	{
		printf("Could not create JSON object: heartbeatFields\n");
		return 1;
	}
	cJSON_AddItemToObject(event, "heartbeatFields", heartbeatFields);

    char *post_data_string = NULL;

	post_data_string = cJSON_PrintUnformatted(postDataJson);

	printf("Post data JSON:\n%s\n", post_data_string);

	if (postDataJson != NULL)
	{
		cJSON_Delete(postDataJson);
	}

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data_string);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		printf("Failed to send cURL...\n");
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

static int send_pnf_registration_instance(char *hostname, int port, bool is_tls)
{
	CURLcode res;

	prepare_ves_message_curl();

	cJSON *postDataJson = cJSON_CreateObject();

	cJSON *event = cJSON_CreateObject();
	if (event == NULL)
	{
		printf("Could not create JSON object: event\n");
		return 1;
	}
	cJSON_AddItemToObject(postDataJson, "event", event);

	char source_name[100];
	sprintf(source_name, "%s_%d", hostname, port);

	cJSON *commonEventHeader = vesCreateCommonEventHeader("pnfRegistration", "EventType5G", source_name);
	if (commonEventHeader == NULL)
	{
		printf("Could not create JSON object: commonEventHeader\n");
		return 1;
	}
	cJSON_AddItemToObject(event, "commonEventHeader", commonEventHeader);

	cJSON *pnfRegistrationFields = vesCreatePnfRegistrationFields(port, is_tls);
	if (pnfRegistrationFields == NULL)
	{
		printf("Could not create JSON object: pnfRegistrationFields\n");
		return 1;
	}
	cJSON_AddItemToObject(event, "pnfRegistrationFields", pnfRegistrationFields);

    char *post_data_string = NULL;

	post_data_string = cJSON_PrintUnformatted(postDataJson);

	printf("Post data JSON:\n%s\n", post_data_string);

	if (postDataJson != NULL)
	{
		cJSON_Delete(postDataJson);
	}

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data_string);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		printf("Failed to send cURL...\n");
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

static void pnf_registration(void)
{
	// delay the PNF Registration VES message, until anything else is initialized
	printf("delay the PNF Registration VES message, until anything else is initialized");
	sleep(SLEEP_BEFORE_PNF_AUTOREG);

	int is_reg = getVesRegistrationFromConfigJson();

	if (!is_reg)
	{
		//ves-registration object is set to False, we do not make an automatic PNF registration
		printf("ves-registration object is set to False, we do not make an automatic PNF registration");
		return;
	}

	int rc = SR_ERR_OK, netconf_port_base = 0;
	char *netconf_base_string = getenv("NETCONF_BASE");
	char *hostname_string = getenv("HOSTNAME");

	if (netconf_base_string != NULL)
	{
		rc = sscanf(netconf_base_string, "%d", &netconf_port_base);
		if (rc != 1)
		{
			printf("Could not find the NETCONF base port, aborting the PNF registration...\n");
			return;
		}
	}

	//TODO This is where we hardcoded: 7 devices will have SSH connections and 3 devices will have TLS connections
	for (int port = 0; port < NETCONF_CONNECTIONS_PER_DEVICE - 3; ++port)
	{
		pthread_mutex_lock(&lock);
		rc = send_pnf_registration_instance(hostname_string, netconf_port_base + port, FALSE);
		if (rc != SR_ERR_OK)
		{
			printf("Could not send PNF Registration SSH message...\n");
		}
		pthread_mutex_unlock(&lock);
	}
	for (int port = NETCONF_CONNECTIONS_PER_DEVICE - 3; port < NETCONF_CONNECTIONS_PER_DEVICE; ++port)
	{
		pthread_mutex_lock(&lock);
		rc = send_pnf_registration_instance(hostname_string, netconf_port_base + port, TRUE);
		pthread_mutex_unlock(&lock);
		if (rc != SR_ERR_OK)
		{
			printf("Could not send PNF Registration TLS message...\n");
		}
	}

	return;
}

int
main(int argc, char **argv)
{
    int rc = SR_ERR_OK;

    int heartbeat_interval = 120; //seconds

    setbuf(stdout, NULL);

    if (pthread_mutex_init(&lock, NULL) != 0)
	{
		printf("Mutex init failed...\n");
		goto cleanup;
	}

    pthread_t pnf_autoregistration_thread;
	if(pthread_create(&pnf_autoregistration_thread, NULL, pnf_registration, NULL))
	{
		fprintf(stderr, "Could not create thread for pnf auto registration\n");
		goto cleanup;
	}

    rc = _init_curl();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize cURL: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    while (!exit_application)
    {
    	heartbeat_interval = getVesHeartbeatPeriodFromConfigJson();

    	if (heartbeat_interval > 0)
    	{
    		pthread_mutex_lock(&lock);
			send_heartbeat(heartbeat_interval);
			pthread_mutex_unlock(&lock);
			sleep(heartbeat_interval);
    	}
    	else
    	{
    		sleep(1);
    	}
    }

    printf("Application exit requested, exiting.\n");

cleanup:

    rc = cleanup_curl();

    return rc;
}

