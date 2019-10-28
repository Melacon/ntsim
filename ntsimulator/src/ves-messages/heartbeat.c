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

#include "heartbeat.h"
#include "sysrepo.h"
#include "sysrepo/values.h"

#include "utils.h"

#define LINE_BUFSIZE 128

volatile int exit_application = 0;

static 	CURL *curl;

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

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
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
	struct MemoryStruct curl_response_mem;

	curl_response_mem.memory = malloc(1);  /* will be grown as needed by the realloc above */
	curl_response_mem.size = 0;    /* no data at this point */

	curl_easy_reset(curl);
	set_curl_common_info();

	char *ves_ipv4 = getVesIpv4FromConfigJson();
	int ves_port = getVesPortFromConfigJson();

	char url[100];
	sprintf(url, "http://%s:%d/eventListener/v7", ves_ipv4, ves_port);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	free(ves_ipv4);

//	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

	cJSON *postDataJson = cJSON_CreateObject();

	cJSON *event = cJSON_CreateObject();
	if (event == NULL)
	{
		printf("Could not create JSON object: event\n");
		return 1;
	}
	cJSON_AddItemToObject(postDataJson, "event", event);

	cJSON *commonEventHeader = vesCreateCommonEventHeader();
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
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curl_response_mem);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		printf("Failed to send cURL...\n");
		return 1;
	}

	return SR_ERR_OK;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

int
main(int argc, char **argv)
{
    int rc = SR_ERR_OK;

    int heartbeat_interval = 120; //seconds

    setbuf(stdout, NULL);

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
			send_heartbeat(heartbeat_interval);
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

