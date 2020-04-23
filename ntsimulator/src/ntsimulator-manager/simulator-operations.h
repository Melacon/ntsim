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

#ifndef SRC_NTSIMULATOR_MANAGER_SIMULATOR_OPERATIONS_H_
#define SRC_NTSIMULATOR_MANAGER_SIMULATOR_OPERATIONS_H_

#include <curl/curl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include <cjson/cJSON.h>

#define CURL_MEM_SIZE 2048


/**
 * Storing the device information
*/

typedef struct device {
	char *device_id;
	int netconf_port;
	bool is_mounted;
	char *operational_state;
	struct device *next;
} device_t;

typedef struct device_stack {
	device_t *head;
	size_t stack_size;
} device_stack_t;

#define URL_AND_CREDENTIALS_MAX_LEN 400

typedef struct controller
{
	char url[URL_AND_CREDENTIALS_MAX_LEN];
	char credentials[URL_AND_CREDENTIALS_MAX_LEN];
	char url_for_keystore_add[URL_AND_CREDENTIALS_MAX_LEN];
	char url_for_private_key_add[URL_AND_CREDENTIALS_MAX_LEN];
	char url_for_trusted_ca_add[URL_AND_CREDENTIALS_MAX_LEN];
} controller_t;


device_stack_t *new_device_stack(void);
void push_device(device_stack_t *theStack, char *dev_id, int port);
void pop_device(device_stack_t *theStack);
int get_netconf_port_next(device_stack_t *theStack);
int get_netconf_port_base(void);
char *get_id_last_device(device_stack_t *theStack);
int get_current_number_of_devices(device_stack_t *theStack);
int get_current_number_of_mounted_devices(device_stack_t *theStack);


/**
 * cURL utilities
*/

struct MemoryStruct {
  char *memory;
  size_t size;
};

int _init_curl(void);
int cleanup_curl(void);

int _init_curl_odl(void);
int cleanup_curl_odl(void);

int start_device(device_stack_t *theStack);
int stop_device(device_stack_t *theStack);

int mount_device(device_stack_t *theStack, controller_t controller_details);
int unmount_device(device_stack_t *theStack, controller_t controller_details);

char* get_docker_container_operational_state(device_stack_t *theStack, char *container_id);
int get_docker_containers_operational_state_curl(device_stack_t *theStack);

char* get_docker_container_resource_stats();

int notification_delay_period_changed(sr_val_t *val, size_t count);
int ves_heartbeat_period_changed(int period);
int ves_ip_changed(char *new_ip);
int ves_port_changed(int new_port);
int ves_registration_changed(cJSON_bool new_bool);
int is_netconf_available_changed(cJSON_bool new_bool);
int is_ves_available_changed(cJSON_bool new_bool);
int ssh_connections_changed(int number);
int tls_connections_changed(int number);


int add_key_pair_to_odl(controller_t *controller_list, int controller_list_size);


#endif /* SRC_NTSIMULATOR_MANAGER_SIMULATOR_OPERATIONS_H_ */
