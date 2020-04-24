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
	static int sequence_number = 0;

	prepare_ves_message_curl(curl);

	cJSON *postDataJson = cJSON_CreateObject();
	if (postDataJson == NULL)
	{
		printf("Could not create JSON object: postDataJson\n");
		return 1;
	}

	cJSON *event = cJSON_CreateObject();
	if (event == NULL)
	{
		printf("Could not create JSON object: event\n");
		return 1;
	}
	cJSON_AddItemToObject(postDataJson, "event", event);

	char hostname[100];
	sprintf(hostname, "%s", getenv("HOSTNAME"));

	cJSON *commonEventHeader = vesCreateCommonEventHeader("heartbeat", "Controller", hostname, sequence_number++);
	if (commonEventHeader == NULL)
	{
		printf("Could not create JSON object: commonEventHeader\n");
		cJSON_Delete(postDataJson);
		return 1;
	}
	cJSON_AddItemToObject(event, "commonEventHeader", commonEventHeader);

	cJSON *heartbeatFields = vesCreateHeartbeatFields(heartbeat_interval);
	if (heartbeatFields == NULL)
	{
		printf("Could not create JSON object: heartbeatFields\n");
		cJSON_Delete(postDataJson);
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
	static int sequence_number = 0;

	prepare_ves_message_curl(curl);

	cJSON *postDataJson = cJSON_CreateObject();
	if (postDataJson == NULL)
	{
		printf("Could not create JSON object: postDataJson\n");
		return 1;
	}

	cJSON *event = cJSON_CreateObject();
	if (event == NULL)
	{
		printf("Could not create JSON object: event\n");
		cJSON_Delete(postDataJson);
		return 1;
	}
	cJSON_AddItemToObject(postDataJson, "event", event);

	char source_name[100];
	sprintf(source_name, "%s_%d", hostname, port);

	cJSON *commonEventHeader = vesCreateCommonEventHeader("pnfRegistration", "EventType5G", source_name, sequence_number++);
	if (commonEventHeader == NULL)
	{
		printf("Could not create JSON object: commonEventHeader\n");
		cJSON_Delete(postDataJson);
		return 1;
	}
	cJSON_AddItemToObject(event, "commonEventHeader", commonEventHeader);

	cJSON *pnfRegistrationFields = vesCreatePnfRegistrationFields(port, is_tls);
	if (pnfRegistrationFields == NULL)
	{
		printf("Could not create JSON object: pnfRegistrationFields\n");
		cJSON_Delete(postDataJson);
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

static void *pnf_registration(void *arg)
{
	// delay the PNF Registration VES message, until anything else is initialized
	printf("delay the PNF Registration VES message, until anything else is initialized");
	sleep(SLEEP_BEFORE_PNF_AUTOREG);

	int is_reg = getVesRegistrationFromConfigJson();

	if (!is_reg)
	{
		//ves-registration object is set to False, we do not make an automatic PNF registration
		printf("ves-registration object is set to False, we do not make an automatic PNF registration");
		return NULL;
	}

	int rc = SR_ERR_OK, netconf_port_base = 0;
	char *hostname_string = getenv("HOSTNAME");
    int port = 0;

    netconf_port_base = getIntFromString(getenv("NETCONF_BASE"), 0);

	//TODO This is where we hardcoded: 7 devices will have SSH connections and 3 devices will have TLS connections
	for (int i = 0; i < SSH_CONNECTIONS_PER_DEVICE; ++port, ++i)
	{
		pthread_mutex_lock(&lock);
		rc = send_pnf_registration_instance(hostname_string, netconf_port_base + port, FALSE);
		if (rc != SR_ERR_OK)
		{
			printf("Could not send PNF Registration SSH message...\n");
		}
		pthread_mutex_unlock(&lock);
	}
	for (int i = 0; port < TLS_CONNECTIONS_PER_DEVICE; ++port, ++i)
	{
		pthread_mutex_lock(&lock);
		rc = send_pnf_registration_instance(hostname_string, netconf_port_base + port, TRUE);
		pthread_mutex_unlock(&lock);
		if (rc != SR_ERR_OK)
		{
			printf("Could not send PNF Registration TLS message...\n");
		}
	}

	return NULL;
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

