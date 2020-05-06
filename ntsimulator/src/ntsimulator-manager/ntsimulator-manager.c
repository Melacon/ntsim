/*************************************************************************
*
* Copyright 2019 highstreet technologies GmbH and others
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
***************************************************************************/


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

    char *ipv6 = strchr(odl_ip->data.string_val, ':');
    char odl_ip_string[URL_AND_CREDENTIALS_MAX_LEN];
    if (ipv6 != NULL)
    {
        sprintf(odl_ip_string, "[%s]", odl_ip->data.string_val);
    }
    else
    {
        sprintf(odl_ip_string, "%s", odl_ip->data.string_val);
    }


    //URL used for mounting/unmounting a device; the device name needs to be appended
   char url[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url, "http://%s:%d/restconf/config/network-topology:network-topology/topology/"
		 "topology-netconf/node/",
		 odl_ip_string, odl_port->data.uint32_val);

   char credentials[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(credentials, "%s:%s", odl_username->data.string_val, odl_password->data.string_val);

   //URLs used for adding key pair to ODL, for TLS connections
   char url_for_keystore_add[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url_for_keystore_add, "http://%s:%d/restconf/operations/netconf-keystore:add-keystore-entry",
			 odl_ip_string, odl_port->data.uint32_val);

   char url_for_private_key_add[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url_for_private_key_add, "http://%s:%d/restconf/operations/netconf-keystore:add-private-key",
			 odl_ip_string, odl_port->data.uint32_val);

   char url_for_trusted_ca_add[URL_AND_CREDENTIALS_MAX_LEN];
   sprintf(url_for_trusted_ca_add, "http://%s:%d/restconf/operations/netconf-keystore:add-trusted-certificate",
			 odl_ip_string, odl_port->data.uint32_val);

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

    if (strcmp(getenv("K8S_DEPLOYMENT"), "true") == 0)
    {
        if (new_value != simulated_devices_config)
        {
            simulated_devices_config = new_value;
            rc = send_k8s_scale(new_value);
            if (rc != SR_ERR_OK)
            {
                printf("Could not send new_scale=%d to k8s cluster.\n", new_value);
            }
        }
        return SR_ERR_OK;
    }

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
            if (rc != SR_ERR_OK)
            {
                printf("ERROR: Could not start simulated device. Ignoring, trying with the next simulated device, if any...\n");
            }
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

    sr_val_t *val = NULL;

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
	val = NULL;

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
			val = NULL;
    		return SR_ERR_OK;
    	}

		rc = mounted_devices_changed(session, val->data.uint32_val);
		if (rc != SR_ERR_OK) {
			goto sr_error;
		}
    }

    sr_free_val(val);
	val = NULL;

    size_t count = 0;

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_items(session, "/network-topology-simulator:simulator-config/notification-config/fault-notification-delay-period", &val, &count);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    rc = notification_delay_period_changed(val, count);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }
    sr_free_values(val, count);
	val = NULL;

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
	val = NULL;

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
	val = NULL;

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
	val = NULL;

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
	val = NULL;

	/* get the value from sysrepo, we do not care if the value did not change in our case */
	rc = sr_get_item(session, "/network-topology-simulator:simulator-config/notification-config/is-netconf-available", &val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	rc = is_netconf_available_changed(val->data.bool_val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	sr_free_val(val);
	val = NULL;

	/* get the value from sysrepo, we do not care if the value did not change in our case */
	rc = sr_get_item(session, "/network-topology-simulator:simulator-config/notification-config/is-ves-available", &val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	rc = is_ves_available_changed(val->data.bool_val);
	if (rc != SR_ERR_OK) {
		goto sr_error;
	}

	sr_free_val(val);
	val = NULL;

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_item(session, "/network-topology-simulator:simulator-config/ssh-connections", &val);
    if (rc != SR_ERR_OK) {
        printf("NTS Manager /network-topology-simulator:simulator-config/ssh-connections object not available, ignoring..");
    }
    else
    {
        rc = ssh_connections_changed(val->data.uint32_val);
        if (rc != SR_ERR_OK) {
            goto sr_error;
        }

        if (strcmp(getenv("K8S_DEPLOYMENT"), "true") == 0)
        {
            rc = send_k8s_extend_port();
            if (rc != SR_ERR_OK)
            {
                printf("Could not send the extended port to k8s cluster.\n");
            }
        }
    }

    sr_free_val(val);
	val = NULL;

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_item(session, "/network-topology-simulator:simulator-config/tls-connections", &val);
    if (rc != SR_ERR_OK) {
        printf("NTS Manager /network-topology-simulator:simulator-config/tls-connections object not available, ignoring..");
    }
    else
    {
        rc = tls_connections_changed(val->data.uint32_val);
        if (rc != SR_ERR_OK) {
            goto sr_error;
        }

        if (strcmp(getenv("K8S_DEPLOYMENT"), "true") == 0)
        {
            rc = send_k8s_extend_port();
            if (rc != SR_ERR_OK)
            {
                printf("Could not send the extended port to k8s cluster.\n");
            }
        }
    }

    sr_free_val(val);
	val = NULL;

    return SR_ERR_OK;

sr_error:
	printf("NTSimulator config change callback failed: %s.", sr_strerror(rc));
	if (val != NULL)
	{
		sr_free_val(val);
		val = NULL;
	}
	return rc;
}

static int
simulator_status_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
        uint64_t request_id, const char *original_xpath, void *private_ctx)
{
	int rc;

	// printf("\n\n ========== Called simulator_status_cb for xpath: %s ==========\n\n", xpath);

    counterAlarms ves_counter, netconf_counter;
    rc = compute_notifications_count(&ves_counter, &netconf_counter);
    if (rc != SR_ERR_OK)
    {
        printf("Could not compute the total number of notification count.\n");
    }

	if (sr_xpath_node_name_eq(xpath, "simulated-devices-list")) 
    {
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
            return SR_ERR_OPERATION_FAILED;
        }

		device_t *current_device = device_list->head;

		while (current_device != NULL)
		{
            counterAlarms vesCount, netconfCount;
            rc = getDeviceCounters(current_device->device_id, &vesCount, &netconfCount);
            if (rc != SR_ERR_OK)
            {
                printf("Could not get Notification Counters for device with uuid=\"%s\"", current_device->device_id);
            }            

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

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/ves-notifications/%s", xpath, current_device->device_id, "normal");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = vesCount.normal;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/ves-notifications/%s", xpath, current_device->device_id, "warning");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = vesCount.warning;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/ves-notifications/%s", xpath, current_device->device_id, "minor");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = vesCount.minor;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/ves-notifications/%s", xpath, current_device->device_id, "major");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = vesCount.major;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/ves-notifications/%s", xpath, current_device->device_id, "critical");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = vesCount.critical;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/netconf-notifications/%s", xpath, current_device->device_id, "normal");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = netconfCount.normal;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/netconf-notifications/%s", xpath, current_device->device_id, "warning");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = netconfCount.warning;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/netconf-notifications/%s", xpath, current_device->device_id, "minor");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = netconfCount.minor;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/netconf-notifications/%s", xpath, current_device->device_id, "major");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = netconfCount.major;

            CREATE_NEW_VALUE(rc, v, current_num_of_values);

            sr_val_build_xpath(&v[current_num_of_values - 1], "%s[uuid='%s']/notification-count/netconf-notifications/%s", xpath, current_device->device_id, "critical");
            v[current_num_of_values - 1].type = SR_UINT32_T;
            v[current_num_of_values - 1].data.uint32_val = netconfCount.critical;

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
     else if (sr_xpath_node_name_eq(xpath, "total-ves-notifications"))
     {
        sr_val_t *v;
        /* convenient functions such as this can be found in sysrepo/values.h */
        size_t current_num_of_values= 0;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "normal");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = ves_counter.normal;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "warning");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = ves_counter.warning;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "minor");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = ves_counter.minor;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "major");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = ves_counter.major;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "critical");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = ves_counter.critical;

        //return the values that we have just created
        *values = v;
        *values_cnt = current_num_of_values;
     }
     else if (sr_xpath_node_name_eq(xpath, "total-netconf-notifications"))
     {
        sr_val_t *v;
        /* convenient functions such as this can be found in sysrepo/values.h */
        size_t current_num_of_values= 0;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "normal");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = netconf_counter.normal;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "warning");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = netconf_counter.warning;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "minor");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = netconf_counter.minor;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "major");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = netconf_counter.major;

        CREATE_NEW_VALUE(rc, v, current_num_of_values);

        sr_val_build_xpath(&v[current_num_of_values - 1], "%s/%s", xpath, "critical");
        v[current_num_of_values - 1].type = SR_UINT32_T;
        v[current_num_of_values - 1].data.uint32_val = netconf_counter.critical;

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
		return SR_ERR_OPERATION_FAILED;
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

    rc = _init_curl_k8s();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize cURL for K8S connection: %s\n", sr_strerror(rc));
    }

    device_list = new_device_stack();
    rc = _init_curl();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize cURL: %s\n", sr_strerror(rc));
    }

    rc = writeSkeletonConfigFile();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize configuration JSON file: %s\n", sr_strerror(rc));
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

    // setting the values that come in an ENV variable as defaults - ves-heartbeat-period
    int vesHeartbeatPeriod = getIntFromString(getenv("VesHeartbeatPeriod"), 0);

    sr_val_t value = { 0 };
    value.type = SR_UINT32_T;
    value.data.uint32_val = vesHeartbeatPeriod;
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/notification-config/ves-heartbeat-period", 
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = ves_heartbeat_period_changed(vesHeartbeatPeriod);
    if (SR_ERR_OK != rc) {
        printf("Error by ves_heartbeat_period_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // setting the values that come in an ENV variable as defaults - is-netconf-available

    int isNetconfAvailable = 1;

    char *isNetconfAvailablString = getenv("IsNetconfAvailable");
    if (isNetconfAvailablString != NULL)
    {
        if (strcmp(isNetconfAvailablString, "false") == 0)
        {
            isNetconfAvailable = 0;
        }
    }

    value = (const sr_val_t) { 0 };
    value.type = SR_BOOL_T;
    value.data.bool_val = isNetconfAvailable;
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/notification-config/is-netconf-available", 
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = is_netconf_available_changed(isNetconfAvailable);
    if (SR_ERR_OK != rc) {
        printf("Error by is_netconf_available_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // setting the values that come in an ENV variable as defaults - is-ves-available

    int isVesAvailable = 1;

    char *isVesAvailablString = getenv("IsVesAvailable");
    if (isVesAvailablString != NULL)
    {
        if (strcmp(isVesAvailablString, "false") == 0)
        {
            isVesAvailable = 0;
        }
    }

    value = (const sr_val_t) { 0 };
    value.type = SR_BOOL_T;
    value.data.bool_val = isVesAvailable;
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/notification-config/is-ves-available", 
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = is_ves_available_changed(isVesAvailable);
    if (SR_ERR_OK != rc) {
        printf("Error by is_ves_available_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // setting the values that come in an ENV variable as defaults - ves-endpoint-port

    int vesEndpointPort = getIntFromString(getenv("VesEndpointPort"), 8080);

    value = (const sr_val_t) { 0 };
    value.type = SR_UINT16_T;
    value.data.uint16_val = vesEndpointPort;
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/ves-endpoint-details/ves-endpoint-port", 
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = ves_port_changed(vesEndpointPort);
    if (SR_ERR_OK != rc) {
        printf("Error by ves_port_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // setting the values that come in an ENV variable as defaults - ves-endpoint-ip

    value = (const sr_val_t) { 0 };
    value.type = SR_STRING_T;
    value.data.string_val = getenv("VesEndpointIp");
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/ves-endpoint-details/ves-endpoint-ip", 
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = ves_ip_changed(getenv("VesEndpointIp"));
    if (SR_ERR_OK != rc) {
        printf("Error by ves_ip_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // setting the values that come in an ENV variable as defaults - ssh-connections

    int sshConnections = getIntFromString(getenv("SshConnections"), 1);

    value = (const sr_val_t) { 0 };
    value.type = SR_UINT32_T;
    value.data.uint32_val = sshConnections;
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/ssh-connections",
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = ssh_connections_changed(sshConnections);
    if (SR_ERR_OK != rc) {
        printf("Error by ssh_connections_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // setting the values that come in an ENV variable as defaults - tls-connections

    int tlsConnections = getIntFromString(getenv("TlsConnections"), 0);

    value = (const sr_val_t) { 0 };
    value.type = SR_UINT32_T;
    value.data.uint32_val = tlsConnections;
    rc = sr_set_item(session, "/network-topology-simulator:simulator-config/tls-connections",
            &value, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_set_item: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    rc = tls_connections_changed(tlsConnections);
    if (SR_ERR_OK != rc) {
        printf("Error by tls_connections_changed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    if (strcmp(getenv("K8S_DEPLOYMENT"), "true") == 0)
    {
        rc = send_k8s_extend_port();
        if (rc != SR_ERR_OK)
        {
            printf("Could not send the number of ports to k8s cluster\n");
        }
    }

    //commit the changes that we have done until now
    rc = sr_commit(session);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_commit: %s\n", sr_strerror(rc));
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

    rc = notification_delay_period_changed(NULL, 0);
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

    rc = writeSkeletonStatusFile();
    if (rc != SR_ERR_OK)
    {
        fprintf(stderr, "Could not initialize status JSON file: %s\n", sr_strerror(rc));
    }

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
    rc = cleanup_curl_k8s();

    return rc;
}

static void clean_current_docker_configuration(void)
{
    if (strcmp(getenv("K8S_DEPLOYMENT"), "true"))
    {
        return;
    }

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
