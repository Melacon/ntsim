/*
 * core-model.c
 *
 *  Created on: Feb 19, 2019
 *      Author: parallels
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include "utils.h"
#include "simulator-operations.h"

volatile int exit_application = 0;

volatile unsigned int simulated_devices_config = 0;
volatile unsigned int mounted_devices_config = 0;


static device_stack_t *device_list = NULL;

controller_t controller_details;

#define XPATH_MAX_LEN 500
#define CONTROLLER_LIST_MAX_LEN 1

static void
print_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN] = {0};
    snprintf(xpath, XPATH_MAX_LEN, "/%s:*//.", module_name);

    sr_val_t *odl_ip = NULL;
    sr_val_t *odl_port = NULL;
    sr_val_t *odl_username = NULL;
    sr_val_t *odl_password = NULL;

    rc = sr_get_items(session, xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_get_items: %s\n", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){

        sr_print_val(&values[i]);

        if (sr_xpath_node_name_eq(values[i].xpath, "controller-ip"))
        {
        	rc = sr_dup_val(&values[i], &odl_ip);
        }
        else if (sr_xpath_node_name_eq(values[i].xpath, "controller-port"))
        {
        	rc = sr_dup_val(&values[i], &odl_port);
        }
        else if (sr_xpath_node_name_eq(values[i].xpath, "controller-username"))
        {
        	rc = sr_dup_val(&values[i], &odl_username);
        }
        else if (sr_xpath_node_name_eq(values[i].xpath, "controller-password"))
        {
        	rc = sr_dup_val(&values[i], &odl_password);
        }
    }

    //URL used for mounting/unmounting a device; the device name needs to be appended
   char url[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url, "http://%s:%d/restconf/config/network-topology:network-topology/topology/"
		 "topology-netconf/node/",
		 odl_ip->data.string_val, odl_port->data.uint32_val);

   char credentials[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(credentials, "%s:%s", odl_username->data.string_val, odl_password->data.string_val);

   //URLs used for adding key pair to ODL, for TLS connections
   char url_for_keystore_add[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url_for_keystore_add, "http://%s:%d/restconf/operations/netconf-keystore:add-keystore-entry",
			 odl_ip->data.string_val, odl_port->data.uint32_val);

   char url_for_private_key_add[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url_for_private_key_add, "http://%s:%d/restconf/operations/netconf-keystore:add-private-key",
			 odl_ip->data.string_val, odl_port->data.uint32_val);

   char url_for_trusted_ca_add[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url_for_trusted_ca_add, "http://%s:%d/restconf/operations/netconf-keystore:add-trusted-certificate",
			 odl_ip->data.string_val, odl_port->data.uint32_val);

   strcpy(controller_details.url, url);
   strcpy(controller_details.credentials, credentials);
   strcpy(controller_details.url_for_keystore_add, url_for_keystore_add);
   strcpy(controller_details.url_for_private_key_add, url_for_private_key_add);
   strcpy(controller_details.url_for_trusted_ca_add, url_for_trusted_ca_add);

   sr_free_val(odl_ip);
   sr_free_val(odl_port);
   sr_free_val(odl_username);
   sr_free_val(odl_password);

    sr_free_values(values, count);
}

static void clean_current_docker_configuration(void);

static int simulated_devices_changed(int new_value)
{
	int rc = SR_ERR_OK;

    if (simulated_devices_config > new_value)
    {
    	//we are configuring less elements that currently
    	for (int i = 0; i < simulated_devices_config - new_value; ++i)
    	{
    		rc = stop_device(device_list);
    	}
    }
    else if (simulated_devices_config < new_value)
    {
    	//we are configuring more elements that currently
    	for (int i = 0; i < new_value - simulated_devices_config; ++i)
    	{
    		rc = start_device(device_list);
    	}
    }

    simulated_devices_config = new_value;

    return rc;
}

int mounted_devices_changed(sr_session_ctx_t *session, int new_value)
{
	int rc = SR_ERR_OK;

	if (mounted_devices_config > new_value)
	{
	  //we need have less mounted elements
	  for (int i = 0; i < mounted_devices_config - new_value; ++i)
	  {
		  printf("Sending unmount device...\n");
		  rc = unmount_device(device_list, controller_details);
	  }
	}
	else if (mounted_devices_config < new_value)
	{
	  //we are configuring more elements that currently
	  for (int i = 0; i < new_value - mounted_devices_config; ++i)
	  {
		  printf("Sending mount device...\n");
		  rc = mount_device(device_list, controller_details);
	  }
	}

	mounted_devices_config = new_value;

    return rc;
}

static int
simulator_config_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	int rc;

    printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG %s: ==========\n\n", module_name);
    print_current_config(session, module_name);

    sr_val_t *val;

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_item(session, "/network-topology-simulator:simulator-config/simulated-devices", &val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    rc = simulated_devices_changed(val->data.uint32_val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    sr_free_val(val);

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_item(session, "/network-topology-simulator:simulator-config/mounted-devices", &val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    if (mounted_devices_config != val->data.uint32_val)
    {
    	if (val->data.uint32_val > simulated_devices_config)
    	{
    		printf("Cannot set mount value greater than number of simulated devices.\n");
    		sr_free_val(val);
    		return SR_ERR_OK;
    	}

		rc = mounted_devices_changed(session, val->data.uint32_val);
		if (rc != SR_ERR_OK) {
			goto sr_error;
		}
    }

    sr_free_val(val);

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_item(session, "/network-topology-simulator:simulator-config/notification-config/fault-notification-delay-period", &val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    rc = notification_delay_period_changed(val->data.uint32_val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    sr_free_val(val);

    /* get the value from sysrepo, we do not care if the value did not change in our case */
	rc = sr_get_item(session, "/network-topology-simulator:simulator-config/notification-config/ves-heartbeat-period", &val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	rc = ves_heartbeat_period_changed(val->data.uint32_val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	sr_free_val(val);

	/* get the value from sysrepo, we do not care if the value did not change in our case */
	rc = sr_get_item(session, "/network-topology-simulator:simulator-config/ves-endpoint-details/ves-endpoint-ip", &val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	rc = ves_ip_changed(val->data.string_val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	sr_free_val(val);

	/* get the value from sysrepo, we do not care if the value did not change in our case */
	rc = sr_get_item(session, "/network-topology-simulator:simulator-config/ves-endpoint-details/ves-endpoint-port", &val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	rc = ves_port_changed(val->data.uint16_val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	sr_free_val(val);

	/* get the value from sysrepo, we do not care if the value did not change in our case */
	rc = sr_get_item(session, "/network-topology-simulator:simulator-config/ves-endpoint-details/ves-registration", &val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	rc = ves_registration_changed(val->data.bool_val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	sr_free_val(val);

    return SR_ERR_OK;

sr_error:
	printf("NTSimulator config change callback failed: %s.", sr_strerror(rc));
	return rc;
}

static int
simulator_status_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
        uint64_t request_id, const char *original_xpath, void *private_ctx)
{
	int rc;

	printf("\n\n ========== Called simulator_status_cb for xpath: %s ==========\n\n", xpath);

	if (sr_xpath_node_name_eq(xpath, "simulated-devices-list")) {
		sr_val_t *v;
		size_t current_num_of_values= 0;

		if (simulated_devices_config == 0) //nothing to return if no devices are running
		{
			*values = NULL;
			*values_cnt = 0;

			return SR_ERR_OK;
		}

		rc = get_docker_containers_operational_state_curl(device_list);
		if (rc != SR_ERR_OK)
		{
			printf("Could not get the operational state for the devices simulated.\n");
		}

		device_t *current_device = device_list->head;

		while (current_device != NULL)
		{
			CREATE_NEW_VALUE(rc, v, current_num_of_values);

			sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/%s", xpath, current_device->device_id, "device-ip");
			v[current_num_of_values - 1].type = SR_STRING_T;
			v[current_num_of_values - 1].data.string_val = getenv("NTS_IP");

			for (int i = 0; i < NETCONF_CONNECTIONS_PER_DEVICE; ++i)
			{
				CREATE_NEW_VALUE(rc, v, current_num_of_values);

				sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/%s", xpath, current_device->device_id, "device-port");
				v[current_num_of_values - 1].type = SR_UINT32_T;
				v[current_num_of_values - 1].data.uint32_val = current_device->netconf_port + i;
			}

			CREATE_NEW_VALUE(rc, v, current_num_of_values);

			sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/%s", xpath, current_device->device_id, "is-mounted");
			v[current_num_of_values - 1].type = SR_BOOL_T;
			v[current_num_of_values - 1].data.bool_val = current_device->is_mounted;

			char *operational_state = get_docker_container_operational_state(device_list, current_device->device_id);

			CREATE_NEW_VALUE(rc, v, current_num_of_values);

			sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/%s", xpath, current_device->device_id, "operational-state");
			sr_val_build_str_data(&v[current_num_of_values - 1], SR_ENUM_T, "%s", operational_state);

			current_device = current_device->next;
		}

		//return the values that we have just created
		*values = v;
		*values_cnt = current_num_of_values;
	 }
	 else if (sr_xpath_node_name_eq(xpath, "simulation-usage-details"))
	 {
		float cpu_usage = 0.0, mem_usage = 0.0;

		char *resource_usage_from_script = get_docker_container_resource_stats();

		if (resource_usage_from_script != NULL)
		{
			printf("Received line: %s\n", resource_usage_from_script);
			sscanf(resource_usage_from_script, "CPU=%f%%;RAM=%fMiB", &cpu_usage, &mem_usage);
			printf("Read cpu=\"%f\" and mem=\"%f\"\n", cpu_usage, mem_usage);
			free(resource_usage_from_script);
		}

		sr_val_t *v;
		/* convenient functions such as this can be found in sysrepo/values.h */
		size_t current_num_of_values= 0;

		CREATE_NEW_VALUE(rc, v, current_num_of_values);

		sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "running-simulated-devices");
		v[current_num_of_values - 1].type = SR_UINT32_T;
		v[current_num_of_values - 1].data.uint32_val = get_current_number_of_devices(device_list);

		CREATE_NEW_VALUE(rc, v, current_num_of_values);

		sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "running-mounted-devices");
		v[current_num_of_values - 1].type = SR_UINT32_T;
		v[current_num_of_values - 1].data.uint32_val = get_current_number_of_mounted_devices(device_list);

		CREATE_NEW_VALUE(rc, v, current_num_of_values);

		sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "base-netconf-port");
		v[current_num_of_values - 1].type = SR_UINT32_T;
		v[current_num_of_values - 1].data.uint32_val = get_netconf_port_base();

		CREATE_NEW_VALUE(rc, v, current_num_of_values);

		sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "cpu-usage");
		v[current_num_of_values - 1].type = SR_DECIMAL64_T;
		v[current_num_of_values - 1].data.decimal64_val = cpu_usage;

		CREATE_NEW_VALUE(rc, v, current_num_of_values);

		sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "mem-usage");
		v[current_num_of_values - 1].type = SR_UINT32_T;
		v[current_num_of_values - 1].data.uint32_val = (int)mem_usage;

		//return the values that we have just created
		*values = v;
		*values_cnt = current_num_of_values;
	 }

    return SR_ERR_OK;
}

int odl_add_key_pair_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
		sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
	int rc = SR_ERR_OK;
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;
	controller_t controller_list[CONTROLLER_LIST_MAX_LEN];
	int controller_list_size = 0;

	controller_list[0] = controller_details;
	controller_list_size++;

	for (int i = 0; i < controller_list_size; ++i)
	{
		printf("%d iteration: Got back url=%s and credentials=%s\n", i, controller_list[i].url, controller_list[i].credentials);
	}

	rc = add_key_pair_to_odl(controller_list, controller_list_size);
	if (rc != SR_ERR_OK)
	{
		printf("Failed to add key pair to ODL.\n");
	}

	return rc;
}


static void
sigint_handler(int signum)
{
    exit_application = 1;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    setbuf(stdout, NULL);

    device_list = new_device_stack();
    rc = _init_curl();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize cURL: %s\n", sr_strerror(rc));
    }

    /* connect to sysrepo */
    rc = sr_connect("network-topology-simulator", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

	/* read startup config */
	printf("\n\n ========== READING STARTUP CONFIG network-topology-simulator: ==========\n\n");
	print_current_config(session, "network-topology-simulator");

	/* subscribe for changes in running config */
	rc = sr_module_change_subscribe(session, "network-topology-simulator", simulator_config_change_cb, NULL,
			0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
	if (SR_ERR_OK != rc) {
		fprintf(stderr, "Error by sr_module_change_subscribe: %s\n", sr_strerror(rc));
		goto cleanup;
	}

    /* subscribe as state data provider for the ntsimulator state data */
    rc = sr_dp_get_items_subscribe(session, "/network-topology-simulator:simulator-status", simulator_status_cb, NULL,
    		SR_SUBSCR_CTX_REUSE, &subscription);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    rc = notification_delay_period_changed(0);
    if (rc != SR_ERR_OK) {
    	printf("Could not write the delay period to file!\n");
        goto cleanup;
    }

    rc = _init_curl_odl();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize cURL for ODL connection: %s\n", sr_strerror(rc));
    }

    rc = sr_rpc_subscribe(session, "/network-topology-simulator:add-key-pair-to-odl", odl_add_key_pair_cb, (void *)session,
    		SR_SUBSCR_CTX_REUSE, &subscription);

	printf("\n\n ========== STARTUP CONFIG network-topology-simulator APPLIED AS RUNNING ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    while (!exit_application) {

		sleep(1);  /* or do some more useful work... */
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(session, subscription);
    }
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }

    clean_current_docker_configuration();
    rc = cleanup_curl();
    rc = cleanup_curl_odl();

    return rc;
}

static void clean_current_docker_configuration(void)
{
	printf("Cleaning docker containers...\n");

	if (device_list == NULL)
	{
		return;
	}

	for (int i = 0; i < simulated_devices_config; ++i)
	{
		stop_device(device_list);
	}

	printf("Cleaning completed!\n");
}
