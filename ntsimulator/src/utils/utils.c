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

#include "utils.h"

#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

void set_curl_common_info_ves(CURL *curl)
{
	struct curl_slist *chunk = NULL;
	chunk = curl_slist_append(chunk, "Content-Type: application/json");
	chunk = curl_slist_append(chunk, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L); // seconds timeout for a connection
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); //seconds timeout for an operation

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
}

void getCurrentDateAndTime(char *date_and_time)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	int millisec;

	gettimeofday(&tv, NULL);
	millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
	if (millisec>=1000)
	{ // Allow for rounding up to nearest second
		millisec -=1000;
		tv.tv_sec++;
		millisec /= 100;
	}
	sprintf(date_and_time, "%04d-%02d-%02dT%02d:%02d:%02d.%01dZ",
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	tm.tm_hour, tm.tm_min, tm.tm_sec, millisec/100);

	return;
}

void	generateRandomMacAddress(char *mac_address)
{
	long rand1, rand2, rand3, rand4, rand5, rand6;
	rand1 = random_at_most(255);
	rand2 = random_at_most(255);
	rand3 = random_at_most(255);
	rand4 = random_at_most(255);
	rand5 = random_at_most(255);
	rand6 = random_at_most(255);

	sprintf(mac_address, "%02X:%02X:%02X:%02X:%02X:%02X", rand1, rand2, rand3, rand4, rand5, rand6);

	return;
}

long random_at_most(long max) 
{
    unsigned long
        // max <= RAND_MAX < ULONG_MAX, so this is okay.
        num_bins = (unsigned long) max + 1,
        num_rand = (unsigned long) RAND_MAX + 1,
        bin_size = num_rand / num_bins,
        defect   = num_rand % num_bins;

    unsigned int seed;
    FILE* urandom = fopen("/dev/urandom", "r");
    fread(&seed, sizeof(int), 1, urandom);
    fclose(urandom);
    srandom(seed);

    long x;
    do 
    {
        x = random();
    }
    // This is carefully written not to overflow
    while (num_rand - defect <= (unsigned long)x);

    // Truncated division is intentional
    return x/bin_size;
}

int getSecondsFromLastQuarterInterval(void)
{
	time_t t = time(NULL);
	time_t t_past = time(NULL);
	struct tm tm = *localtime(&t);
	struct tm tm_15_min_ago = tm;

	//round to the last quarter hour
	tm_15_min_ago.tm_min -= (tm_15_min_ago.tm_min % 15);
	tm_15_min_ago.tm_sec = 0;

	t=mktime(&tm_15_min_ago);
	t_past=mktime(&tm);

	double seconds = difftime(t_past, t);

	return (int)seconds;
}

int getSecondsFromLastDayInterval(void)
{
	time_t t = time(NULL);
	time_t t_past = time(NULL);
	struct tm tm = *localtime(&t);
	struct tm tm_day_ago = tm;

	//round to the last quarter hour
	tm_day_ago.tm_hour = 0;
	tm_day_ago.tm_min = 0;
	tm_day_ago.tm_sec = 0;

	t=mktime(&tm_day_ago);
	t_past=mktime(&tm);

	double seconds = difftime(t_past, t);

	return (int)seconds;
}

void getPreviousQuarterInterval(int number_of_intervals, char *date_and_time)
{
	time_t t = time(NULL);
	t -= 15 * 60 * number_of_intervals;
	struct tm tm = *localtime(&t);

	tm.tm_min -= (tm.tm_min % 15);
	tm.tm_sec = 0;

	sprintf(date_and_time, "%04d-%02d-%02dT%02d:%02d:%02d.0Z",
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	tm.tm_hour, tm.tm_min, tm.tm_sec);

	return;
}

void getPreviousDayPmTimestamp(int number_of_intervals, char *date_and_time)
{
	time_t t = time(NULL);
	t -= 24 * 60 * 60 * number_of_intervals;
	struct tm tm = *localtime(&t);

	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;

	sprintf(date_and_time, "%04d-%02d-%02dT%02d:%02d:%02d.0Z",
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	tm.tm_hour, tm.tm_min, tm.tm_sec);

	return;
}

long int getMicrosecondsSinceEpoch(void)
{
	time_t t = time(NULL);
	struct timeval tv;
	long int useconds;

	gettimeofday(&tv, NULL);
	useconds = t*1000 + tv.tv_usec; //add the microseconds to the seconds

	return useconds;
}

//TODO need to implement other authentication methods as well, not only no-auth
void prepare_ves_message_curl(CURL *curl)
{
	curl_easy_reset(curl);
	set_curl_common_info_ves(curl);

	char *ves_ip = getVesIpFromConfigJson();
	int ves_port = getVesPortFromConfigJson();

	char url[100];
	sprintf(url, "http://%s:%d/eventListener/v7", ves_ip, ves_port);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	free(ves_ip);

	return;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
cJSON*	vesCreateCommonEventHeader(char *domain, char *event_type, char *source_name, int seq_id)
{
	char dateAndTime[50];
	getCurrentDateAndTime(dateAndTime);

	long useconds = getMicrosecondsSinceEpoch();

	cJSON *commonEventHeader = cJSON_CreateObject();
	if (commonEventHeader == NULL)
	{
		printf("Could not create JSON object: commonEventHeader\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "domain", domain) == NULL)
	{
		printf("Could not create JSON object: domain\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	char eventId[200];
	sprintf(eventId, "%s_%s", source_name, dateAndTime);

	if (cJSON_AddStringToObject(commonEventHeader, "eventId", eventId) == NULL)
	{
		printf("Could not create JSON object: eventId\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	char event_name[200];
	sprintf(event_name, "%s_%s", domain, event_type);

	if (cJSON_AddStringToObject(commonEventHeader, "eventName", event_name) == NULL)
	{
		printf("Could not create JSON object: eventName\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "eventType", event_type) == NULL)
	{
		printf("Could not create JSON object: eventType\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddNumberToObject(commonEventHeader, "sequence", (double)(seq_id)) == NULL)
	{
		printf("Could not create JSON object: sequence\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "priority", "Low") == NULL)
	{
		printf("Could not create JSON object: priority\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "reportingEntityId", "") == NULL)
	{
		printf("Could not create JSON object: reportingEntityId\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "reportingEntityName", source_name) == NULL)
	{
		printf("Could not create JSON object: reportingEntityName\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "sourceId", "") == NULL)
	{
		printf("Could not create JSON object: sourceId\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "sourceName", source_name) == NULL)
	{
		printf("Could not create JSON object: sourceName\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddNumberToObject(commonEventHeader, "startEpochMicrosec", (double)(useconds)) == NULL)
	{
		printf("Could not create JSON object: startEpochMicrosec\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddNumberToObject(commonEventHeader, "lastEpochMicrosec", (double)(useconds)) == NULL)
	{
		printf("Could not create JSON object: lastEpochMicrosec\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "nfNamingCode", "sdn controller") == NULL)
	{
		printf("Could not create JSON object: nfNamingCode\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "nfVendorName", "sdn") == NULL)
	{
		printf("Could not create JSON object: nfVendorName\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "timeZoneOffset", "+00:00") == NULL)
	{
		printf("Could not create JSON object: timeZoneOffset\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "version", "4.0.1") == NULL)
	{
		printf("Could not create JSON object: version\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "vesEventListenerVersion", "7.0.1") == NULL)
	{
		printf("Could not create JSON object: vesEventListenerVersion\n");
		cJSON_Delete(commonEventHeader);
		return NULL;
	}

	return commonEventHeader;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
cJSON*	vesCreateHeartbeatFields(int heartbeat_interval)
{
	char dateAndTime[50];
	getCurrentDateAndTime(dateAndTime);

	cJSON *heartbeatFields = cJSON_CreateObject();
	if (heartbeatFields == NULL)
	{
		printf("Could not create JSON object: heartbeatFields\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(heartbeatFields, "heartbeatFieldsVersion", "3.0") == NULL)
	{
		printf("Could not create JSON object: heartbeatFieldsVersion\n");
		cJSON_Delete(heartbeatFields);
		return NULL;
	}

	if (cJSON_AddNumberToObject(heartbeatFields, "heartbeatInterval", (double)(heartbeat_interval)) == NULL)
	{
		printf("Could not create JSON object: heartbeatInterval\n");
		cJSON_Delete(heartbeatFields);
		return NULL;
	}

	cJSON *additionalFields = cJSON_CreateObject();
	if (additionalFields == NULL)
	{
		printf("Could not create JSON object: additionalFields\n");
		cJSON_Delete(heartbeatFields);
		return NULL;
	}
	cJSON_AddItemToObject(heartbeatFields, "additionalFields", additionalFields);

	if (cJSON_AddStringToObject(additionalFields, "eventTime", dateAndTime) == NULL)
	{
		printf("Could not create JSON object: eventTime\n");
		cJSON_Delete(heartbeatFields);
		return NULL;
	}

	return heartbeatFields;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
char* 	readConfigFileInString(void)
{
	char * buffer = 0;
	long length;
	char config_file[200];
	sprintf(config_file, "%s/configuration.json", getenv("SCRIPTS_DIR"));
	FILE * f = fopen (config_file, "rb");

	if (f)
	{
	  fseek (f, 0, SEEK_END);
	  length = ftell (f);
	  fseek (f, 0, SEEK_SET);
	  buffer = malloc (length + 1);
	  if (buffer)
	  {
	    fread (buffer, 1, length, f);
	  }
	  fclose (f);
	  buffer[length] = '\0';
	}

	if (buffer)
	{
	  return buffer;
	}

	return NULL;
}

void 	writeConfigFile(char *config)
{
	char config_file[200];
	sprintf(config_file, "%s/configuration.json", getenv("SCRIPTS_DIR"));
	FILE * f = fopen (config_file, "w");

	if (f)
	{
		fputs(config, f);
		fclose(f);
	}
	else
	{
		printf("Could not write configuration file");
	}
}

int getFaultNotificationDelayPeriodFromConfigJson(int *period_array, int *count)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *notifConfig = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifConfig))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *faultNotifDelay = cJSON_GetObjectItemCaseSensitive(notifConfig, "fault-notification-delay-period");
	if (!cJSON_IsArray(faultNotifDelay))
	{
		printf("Configuration JSON is not as expected: fault-notification-delay-period is not an array.");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

    cJSON *iterator = NULL;
    *count = 0;
    int i = 0;

    cJSON_ArrayForEach(iterator, faultNotifDelay) 
    {
        if (cJSON_IsNumber(iterator)) 
        {
            period_array[i++] = iterator->valueint;
        } 
        else 
        {
            printf("Invalid number in array!");
        }
    }

    *count = i;

	cJSON_Delete(jsonConfig);

	return SR_ERR_OK;
}

int 	getVesHeartbeatPeriodFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();
	int vesHeartbeat = 0;

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *notifConfig = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifConfig))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesHeartbeatPeriod = cJSON_GetObjectItemCaseSensitive(notifConfig, "ves-heartbeat-period");
	if (!cJSON_IsNumber(vesHeartbeatPeriod))
	{
		printf("Configuration JSON is not as expected: ves-heartbeat-period is not a number");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	vesHeartbeat = (int)(vesHeartbeatPeriod->valuedouble);

	cJSON_Delete(jsonConfig);

	return vesHeartbeat;
}


/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
char* 	getVesAuthMethodFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return NULL;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		cJSON_Delete(jsonConfig);
		return NULL;
	}

	cJSON *vesAuthMethod = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-auth-method");
	if (!cJSON_IsString(vesAuthMethod))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-auth-method is not an object");
		cJSON_Delete(jsonConfig);
		return NULL;
	}

	char *auth_method_string = strdup(cJSON_GetStringValue(vesAuthMethod));

	cJSON_Delete(jsonConfig);

	return auth_method_string;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
char* 	getVesIpFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return NULL;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		cJSON_Delete(jsonConfig);
		return NULL;
	}

	cJSON *vesIp = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-ip");
	if (!cJSON_IsString(vesIp))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-ip is not an object");
		cJSON_Delete(jsonConfig);
		return NULL;
	}

	char *ves_ip = strdup(cJSON_GetStringValue(vesIp));

	cJSON_Delete(jsonConfig);

	return ves_ip;
}

int 	getVesPortFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesPort = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-port");
	if (!cJSON_IsNumber(vesPort))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-port is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	int port = (int)(vesPort->valuedouble);

	cJSON_Delete(jsonConfig);

	return port;
}

int 	getVesRegistrationFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesReg = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-registration");
	if (!cJSON_IsBool(vesReg))
	{
		printf("Configuration JSON is not as expected: ves-registration is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	int is_ves_reg = (cJSON_IsTrue(vesReg)) ? TRUE : FALSE;

	cJSON_Delete(jsonConfig);

	return is_ves_reg;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
cJSON*	vesCreatePnfRegistrationFields(int port, bool is_tls)
{
	cJSON *pnfRegistrationFields = cJSON_CreateObject();
	if (pnfRegistrationFields == NULL)
	{
		printf("Could not create JSON object: pnfRegistrationFields\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "pnfRegistrationFieldsVersion", "2.0") == NULL)
	{
		printf("Could not create JSON object: pnfRegistrationFieldsVersion\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "lastServiceDate", "2019-08-16") == NULL)
	{
		printf("Could not create JSON object: lastServiceDate\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	char mac_addr[40];
	generateRandomMacAddress(mac_addr);

	if (cJSON_AddStringToObject(pnfRegistrationFields, "macAddress", mac_addr) == NULL)
	{
		printf("Could not create JSON object: macAddress\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "manufactureDate", "2019-08-16") == NULL)
	{
		printf("Could not create JSON object: manufactureDate\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "modelNumber", "Simulated Device Melacon") == NULL)
	{
		printf("Could not create JSON object: manufactureDate\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "oamV4IpAddress", getenv("NTS_IP")) == NULL)
	{
		printf("Could not create JSON object: oamV4IpAddress\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "oamV6IpAddress", "0:0:0:0:0:ffff:a0a:011") == NULL)
	{
		printf("Could not create JSON object: oamV6IpAddress\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	char serial_number[100];
	sprintf(serial_number, "%s-%s-%d-Simulated Device Melacon", getenv("HOSTNAME"), getenv("NTS_IP"), port);

	if (cJSON_AddStringToObject(pnfRegistrationFields, "serialNumber", serial_number) == NULL)
	{
		printf("Could not create JSON object: serialNumber\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "softwareVersion", "2.3.5") == NULL)
	{
		printf("Could not create JSON object: softwareVersion\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "unitFamily", "Simulated Device") == NULL)
	{
		printf("Could not create JSON object: unitFamily\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "unitType", "O-RAN-sim") == NULL)
	{
		printf("Could not create JSON object: unitType\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(pnfRegistrationFields, "vendorName", "Melacon") == NULL)
	{
		printf("Could not create JSON object: vendorName\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	cJSON *additionalFields = cJSON_CreateObject();
	if (additionalFields == NULL)
	{
		printf("Could not create JSON object: additionalFields\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}
	cJSON_AddItemToObject(pnfRegistrationFields, "additionalFields", additionalFields);

	char portString[10];
	sprintf(portString, "%d", port);

	if (cJSON_AddStringToObject(additionalFields, "oamPort", portString) == NULL)
	{
		printf("Could not create JSON object: oamPort\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (is_tls)
	{
		//TLS specific configuration
		if (cJSON_AddStringToObject(additionalFields, "protocol", "TLS") == NULL)
		{
			printf("Could not create JSON object: protocol\n");
			cJSON_Delete(pnfRegistrationFields);
			return NULL;
		}

		//TODO here we have the username from the docker container hardcoded: netconf
		if (cJSON_AddStringToObject(additionalFields, "username", "netconf") == NULL)
		{
			printf("Could not create JSON object: username\n");
			cJSON_Delete(pnfRegistrationFields);
			return NULL;
		}

		if (cJSON_AddStringToObject(additionalFields, "keyId", "device-key") == NULL)
		{
			printf("Could not create JSON object: keyId\n");
			cJSON_Delete(pnfRegistrationFields);
			return NULL;
		}
	}
	else
	{
		//SSH specific configuration
		if (cJSON_AddStringToObject(additionalFields, "protocol", "SSH") == NULL)
		{
			printf("Could not create JSON object: protocol\n");
			cJSON_Delete(pnfRegistrationFields);
			return NULL;
		}

		//TODO here we have the username from the docker container hardcoded: netconf
		if (cJSON_AddStringToObject(additionalFields, "username", "netconf") == NULL)
		{
			printf("Could not create JSON object: username\n");
			cJSON_Delete(pnfRegistrationFields);
			return NULL;
		}

		//TODO here we have the password from the docker container hardcoded: netconf
		if (cJSON_AddStringToObject(additionalFields, "password", "netconf") == NULL)
		{
			printf("Could not create JSON object: password\n");
			cJSON_Delete(pnfRegistrationFields);
			return NULL;
		}
	}

	if (cJSON_AddStringToObject(additionalFields, "reconnectOnChangedSchema", "false") == NULL)
	{
		printf("Could not create JSON object: reconnectOnChangedSchema\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(additionalFields, "sleep-factor", "1.5") == NULL)
	{
		printf("Could not create JSON object: sleep-factor\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(additionalFields, "tcpOnly", "false") == NULL)
	{
		printf("Could not create JSON object: tcpOnly\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(additionalFields, "connectionTimeout", "20000") == NULL)
	{
		printf("Could not create JSON object: connectionTimeout\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(additionalFields, "maxConnectionAttempts", "100") == NULL)
	{
		printf("Could not create JSON object: maxConnectionAttempts\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(additionalFields, "betweenAttemptsTimeout", "2000") == NULL)
	{
		printf("Could not create JSON object: betweenAttemptsTimeout\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(additionalFields, "keepaliveDelay", "120") == NULL)
	{
		printf("Could not create JSON object: keepaliveDelay\n");
		cJSON_Delete(pnfRegistrationFields);
		return NULL;
	}

	return pnfRegistrationFields;
}

int 	getNetconfAvailableFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *notifDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifDetails))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *isNetconfAvailable = cJSON_GetObjectItemCaseSensitive(notifDetails, "is-netconf-available");
	if (!cJSON_IsBool(isNetconfAvailable))
	{
		printf("Configuration JSON is not as expected: is-netconf-available is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	int is_netconf_available = (cJSON_IsTrue(isNetconfAvailable)) ? TRUE : FALSE;

	cJSON_Delete(jsonConfig);

	return is_netconf_available;
}

int 	getVesAvailableFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();

	if (stringConfig == NULL)
	{
		printf("Could not read JSON configuration file in string.");
		return 0;
	}

	cJSON *jsonConfig = cJSON_Parse(stringConfig);
	if (jsonConfig == NULL)
	{
		free(stringConfig);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
		}
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);
	stringConfig = NULL;

	cJSON *notifDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifDetails))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *isVesAvailable = cJSON_GetObjectItemCaseSensitive(notifDetails, "is-ves-available");
	if (!cJSON_IsBool(isVesAvailable))
	{
		printf("Configuration JSON is not as expected: is-ves-available is not an object");
		cJSON_Delete(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	int is_netconf_available = (cJSON_IsTrue(isVesAvailable)) ? TRUE : FALSE;

	cJSON_Delete(jsonConfig);

	return is_netconf_available;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
cJSON*	vesCreateFaultFields(char *alarm_condition, char *alarm_object, char *severity, char *date_time, char *specific_problem)
{
	cJSON *faultFields = cJSON_CreateObject();
	if (faultFields == NULL)
	{
		printf("Could not create JSON object: faultFields\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "faultFieldsVersion", "4.0") == NULL)
	{
		printf("Could not create JSON object: faultFieldsVersion\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "alarmCondition", alarm_condition) == NULL)
	{
		printf("Could not create JSON object: alarmCondition\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "alarmInterfaceA", alarm_object) == NULL)
	{
		printf("Could not create JSON object: alarmInterfaceA\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "eventSourceType", "O_RAN_COMPONENT") == NULL)
	{
		printf("Could not create JSON object: eventSourceType\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "specificProblem", specific_problem) == NULL)
	{
		printf("Could not create JSON object: specificProblem\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "eventSeverity", severity) == NULL)
	{
		printf("Could not create JSON object: eventSeverity\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(faultFields, "vfStatus", "Active") == NULL)
	{
		printf("Could not create JSON object: vfStatus\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	cJSON *alarmAdditionalInformation = cJSON_CreateObject();
	if (alarmAdditionalInformation == NULL)
	{
		printf("Could not create JSON object: alarmAdditionalInformation\n");
		cJSON_Delete(faultFields);
		return NULL;
	}
	cJSON_AddItemToObject(faultFields, "alarmAdditionalInformation", alarmAdditionalInformation);

	if (cJSON_AddStringToObject(alarmAdditionalInformation, "eventTime", date_time) == NULL)
	{
		printf("Could not create JSON object: eventTime\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(alarmAdditionalInformation, "equipType", "O-RAN-sim") == NULL)
	{
		printf("Could not create JSON object: equipType\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(alarmAdditionalInformation, "vendor", "Melacon") == NULL)
	{
		printf("Could not create JSON object: vendor\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	if (cJSON_AddStringToObject(alarmAdditionalInformation, "model", "Simulated Device") == NULL)
	{
		printf("Could not create JSON object: model\n");
		cJSON_Delete(faultFields);
		return NULL;
	}

	return faultFields;
}

static cJSON* createSeverityCounters(counterAlarms count)
{
    cJSON *severityCounters = cJSON_CreateObject();
    if (severityCounters == NULL)
    {
        printf("Could not create JSON object: severityCounters\n");
        return NULL;
    }

    if (cJSON_AddNumberToObject(severityCounters, "severity-normal", count.normal) == NULL)
    {
        printf("Could not create JSON object: severity-normal\n");
        return NULL;
    }

    if (cJSON_AddNumberToObject(severityCounters, "severity-warning", count.warning) == NULL)
    {
        printf("Could not create JSON object: severity-warning\n");
        return NULL;
    }

    if (cJSON_AddNumberToObject(severityCounters, "severity-minor", count.minor) == NULL)
    {
        printf("Could not create JSON object: severity-minor\n");
        return NULL;
    }

    if (cJSON_AddNumberToObject(severityCounters, "severity-major", count.major) == NULL)
    {
        printf("Could not create JSON object: severity-major\n");
        return NULL;
    }

    if (cJSON_AddNumberToObject(severityCounters, "severity-critical", count.critical) == NULL)
    {
        printf("Could not create JSON object: severity-critical\n");
        return NULL;
    }

    return severityCounters;
}

void writeStatusFile(char *status)
{
	char status_file[200];
	sprintf(status_file, "%s/status.json", getenv("SCRIPTS_DIR"));
	FILE * f = fopen (status_file, "w");

	if (f)
	{
		fputs(status, f);
		fclose(f);
	}
	else
	{
		printf("Could not write status file!\n");
	}
}

int 	writeSkeletonStatusFile()
{
    cJSON *statusObject = cJSON_CreateObject();
    if (statusObject == NULL)
    {
        printf("Could not create JSON object: statusObject\n");
        return SR_ERR_OPERATION_FAILED;
    }

    // counterAlarms counter = {
    //     .normal = 0,
    //     .warning = 0,
    //     .minor = 0,
    //     .major = 0,
    //     .critical = 0
    // };

    // cJSON *totalVesNotifications = createSeverityCounters(counter);
    // if (totalVesNotifications == NULL)
    // {
    //     printf("Could not create JSON object: totalVesNotifications\n");
    //     cJSON_Delete(statusObject);
    //     return SR_ERR_OPERATION_FAILED;
    // }
    // cJSON_AddItemToObject(statusObject, "total-ves-notifications-sent", totalVesNotifications);

    // cJSON *totalNetconfNotifications = createSeverityCounters(counter);
    // if (totalNetconfNotifications == NULL)
    // {
    //     printf("Could not create JSON object: totalNetconfNotifications\n");
    //     cJSON_Delete(statusObject);
    //     return SR_ERR_OPERATION_FAILED;
    // }
    // cJSON_AddItemToObject(statusObject, "total-netconf-notifications-sent", totalNetconfNotifications);

    cJSON *deviceList = cJSON_CreateArray();
    if (deviceList == NULL)
    {
        printf("Could not create JSON object: deviceList\n");
        cJSON_Delete(statusObject);
        return SR_ERR_OPERATION_FAILED;
	}
    cJSON_AddItemToObject(statusObject, "device-list", deviceList);

    char *status_string = NULL;

    status_string = cJSON_PrintUnformatted(statusObject);

    writeStatusFile(status_string);

    if (status_string != NULL)
    {
        free(status_string);
        status_string = NULL;
    }

    if (statusObject != NULL)
    {
	    cJSON_Delete(statusObject);
    }

    return SR_ERR_OK;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
char* 	readStatusFileInString(void)
{
	char * buffer = 0;
	long length;
	char config_file[200];
	sprintf(config_file, "%s/status.json", getenv("SCRIPTS_DIR"));
	FILE * f = fopen (config_file, "rb");

	if (f)
	{
	  fseek (f, 0, SEEK_END);
	  length = ftell (f);
	  fseek (f, 0, SEEK_SET);
	  buffer = malloc (length + 1);
	  if (buffer)
	  {
	    fread (buffer, 1, length, f);
	  }
	  fclose (f);
	  buffer[length] = '\0';
	}

	if (buffer)
	{
	  return buffer;
	}

	return NULL;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
cJSON*  getDeviceListFromStatusFile(void)
{
    char *stringStatus = readStatusFileInString();

	if (stringStatus == NULL)
	{
		printf("Could not read status file!\n");
		return NULL;
	}

	cJSON *jsonStatus = cJSON_Parse(stringStatus);
	if (jsonStatus == NULL)
	{
		free(stringStatus);
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL)
		{
			fprintf(stderr, "Could not parse JSON status! Error before: %s\n", error_ptr);
		}
		return NULL;
	}
	//we don't need the string anymore
	free(stringStatus);
	stringStatus = NULL;

    return jsonStatus;
}

cJSON* createDeviceListEntry(counterAlarms ves_counter, counterAlarms netconf_counter)
{
    cJSON *deviceListEntry = cJSON_CreateObject();
    if (deviceListEntry == NULL)
    {
        printf("Could not create JSON object: deviceListEntry\n");
        return NULL;
    }

    char hostname[100];
    sprintf(hostname, "%s", getenv("HOSTNAME"));

    if (cJSON_AddStringToObject(deviceListEntry, "device-name", hostname) == NULL)
    {
        printf("Could not create JSON object: device-name\n");
        cJSON_Delete(deviceListEntry);
        return NULL;
    }

    cJSON *vesNotificationsSent = createSeverityCounters(ves_counter);
    if (vesNotificationsSent == NULL)
    {
        printf("Could not create JSON object: vesNotificationsSent\n");
        cJSON_Delete(deviceListEntry);
        return NULL;
    }
    cJSON_AddItemToObject(deviceListEntry, "ves-notifications-sent", vesNotificationsSent);

    cJSON *netconfNotificationsSent = createSeverityCounters(netconf_counter);
    if (netconfNotificationsSent == NULL)
    {
        printf("Could not create JSON object: netconfNotificationsSent\n");
        cJSON_Delete(deviceListEntry);
        return NULL;
    }
    cJSON_AddItemToObject(deviceListEntry, "netconf-notifications-sent", netconfNotificationsSent);

    return deviceListEntry;
}

static void modifySeverityCounters(cJSON **severityCounters, counterAlarms count)
{
    cJSON *severity= cJSON_GetObjectItemCaseSensitive(*severityCounters, "severity-normal");
    if (!cJSON_IsNumber(severity))
    {
        printf("Status JSON is not as expected: severity-normal is not an number");
        return;
    }
    //we set the value of the severity-normal object
    cJSON_SetNumberValue(severity, count.normal);

    severity= cJSON_GetObjectItemCaseSensitive(*severityCounters, "severity-warning");
    if (!cJSON_IsNumber(severity))
    {
        printf("Status JSON is not as expected: severity-warning is not an number");
        return;
    }
    //we set the value of the severity-warning object
    cJSON_SetNumberValue(severity, count.warning);

    severity= cJSON_GetObjectItemCaseSensitive(*severityCounters, "severity-minor");
    if (!cJSON_IsNumber(severity))
    {
        printf("Status JSON is not as expected: severity-minor is not an number");
        return;
    }
    //we set the value of the severity-minor object
    cJSON_SetNumberValue(severity, count.minor);

    severity= cJSON_GetObjectItemCaseSensitive(*severityCounters, "severity-major");
    if (!cJSON_IsNumber(severity))
    {
        printf("Status JSON is not as expected: severity-major is not an number");
        return;
    }
    //we set the value of the severity-major object
	cJSON_SetNumberValue(severity, count.major);

    severity= cJSON_GetObjectItemCaseSensitive(*severityCounters, "severity-critical");
    if (!cJSON_IsNumber(severity))
    {
        printf("Status JSON is not as expected: severity-critical is not an number");
        return;
    }
    //we set the value of the severity-critical object
	cJSON_SetNumberValue(severity, count.critical);

    return;
}

static void modifyDeviceListEntry(cJSON **deviceListEntry, counterAlarms ves_counter, counterAlarms netconf_counter)
{
    cJSON *vesNotificationsSent= cJSON_GetObjectItemCaseSensitive(*deviceListEntry, "ves-notifications-sent");
    if (!cJSON_IsObject(vesNotificationsSent))
    {
        printf("Status JSON is not as expected: ves-notifications-sent is not a object");
        return;
    }

    modifySeverityCounters(&vesNotificationsSent, ves_counter);

    cJSON *netconfNotificationsSent= cJSON_GetObjectItemCaseSensitive(*deviceListEntry, "netconf-notifications-sent");
    if (!cJSON_IsObject(netconfNotificationsSent))
    {
        printf("Status JSON is not as expected: netconf-notifications-sent is not a object");
        return;
    }

    modifySeverityCounters(&netconfNotificationsSent, netconf_counter);
}

int writeStatusNotificationCounters(counterAlarms ves_counter, counterAlarms netconf_counter)
{
	cJSON *jsonStatus = getDeviceListFromStatusFile();

	cJSON *deviceList = cJSON_GetObjectItemCaseSensitive(jsonStatus, "device-list");
	if (!cJSON_IsArray(deviceList))
	{
		printf("Status JSON is not as expected: device-list is not an object");
		cJSON_Delete(jsonStatus);
		return SR_ERR_OPERATION_FAILED;
	}

    int array_size = cJSON_GetArraySize(deviceList);

    int found = 0;
    for (int i=0; i<array_size; ++i)
    {
        cJSON *deviceListEntry = cJSON_GetArrayItem(deviceList, i);
        char hostname[100];
        sprintf(hostname, "%s", getenv("HOSTNAME"));

        cJSON *deviceName = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "device-name");
        if (!cJSON_IsString(deviceName))
        {
            printf("Status JSON is not as expected: device-name is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        char *deviceNameString = cJSON_GetStringValue(deviceName);

        if (strcmp(hostname, deviceNameString) == 0)
        {
            modifyDeviceListEntry(&deviceListEntry, ves_counter, netconf_counter);
            found = 1;
            break;
        }
    }
    if (found == 0)
    {
        cJSON* deviceListEntry = createDeviceListEntry(ves_counter, netconf_counter);
    
        cJSON_AddItemToArray(deviceList, deviceListEntry);  
    }

	//writing the new JSON to the configuration file
	char *stringStatus = cJSON_PrintUnformatted(jsonStatus);
	writeStatusFile(stringStatus);

    if (stringStatus != NULL)
    {
        free(stringStatus);
        stringStatus = NULL;
    }

    if (jsonStatus != NULL)
    {
	    cJSON_Delete(jsonStatus);
    }

	return SR_ERR_OK;
}


int removeDeviceEntryFromStatusFile(char *containerId)
{
    cJSON *jsonStatus = getDeviceListFromStatusFile();

	cJSON *deviceList = cJSON_GetObjectItemCaseSensitive(jsonStatus, "device-list");
	if (!cJSON_IsArray(deviceList))
	{
		printf("Status JSON is not as expected: device-list is not an object");
		cJSON_Delete(jsonStatus);
		return SR_ERR_OPERATION_FAILED;
	}

    int array_size = cJSON_GetArraySize(deviceList);
    int found = array_size;

    for (int i=0; i<array_size; ++i)
    {
        cJSON *deviceListEntry = cJSON_GetArrayItem(deviceList, i);
        char hostname[100];
        sprintf(hostname, "%s", getenv("HOSTNAME"));

        cJSON *deviceName = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "device-name");
        if (!cJSON_IsString(deviceName))
        {
            printf("Status JSON is not as expected: device-name is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        char *deviceNameString = cJSON_GetStringValue(deviceName);

        if (strcmp(containerId, deviceNameString) == 0)
        {
            found = i;
            break;
        }
    }

    if (found < array_size)
    {
        cJSON_DeleteItemFromArray(deviceList, found);
    }
    else
    {
        printf("Could not find status file entry for device with id=\"%s\"", containerId);
    }

	//writing the new JSON to the configuration file
	char *stringStatus = cJSON_PrintUnformatted(jsonStatus);
	writeStatusFile(stringStatus);

    if (stringStatus != NULL)
    {
        free(stringStatus);
        stringStatus = NULL;
    }

    if (jsonStatus != NULL)
    {
        cJSON_Delete(jsonStatus);
    }

	return SR_ERR_OK;
}

int compute_notifications_count(counterAlarms *ves_counter, counterAlarms *netconf_counter)
{
    ves_counter->normal = ves_counter->warning = \
            ves_counter->minor = ves_counter->major = \
            ves_counter->critical = 0;
    netconf_counter->normal = netconf_counter->warning = \
            netconf_counter->minor = netconf_counter->major = \
            netconf_counter->critical = 0;

    cJSON *jsonStatus = getDeviceListFromStatusFile();

    cJSON *deviceList = cJSON_GetObjectItemCaseSensitive(jsonStatus, "device-list");
	if (!cJSON_IsArray(deviceList))
	{
		printf("Status JSON is not as expected: device-list is not an object");
		cJSON_Delete(jsonStatus);
		return SR_ERR_OPERATION_FAILED;
	}

    int array_size = cJSON_GetArraySize(deviceList);

    for (int i=0; i<array_size; ++i)
    {
        cJSON *deviceListEntry = cJSON_GetArrayItem(deviceList, i);

        cJSON *vesNotifications = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "ves-notifications-sent");
        if (!cJSON_IsObject(vesNotifications))
        {
            printf("Status JSON is not as expected: ves-notifications-sent is not an object.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }

        cJSON *severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-normal");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-normal is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        int counter = (int)(severity->valuedouble);
        ves_counter->normal += counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-warning");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-warning is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->warning += counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-minor");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-minor is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->minor += counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-major");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-major is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->major += counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-critical");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-critical is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->critical += counter;

        cJSON *netconfNotifications = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "netconf-notifications-sent");
        if (!cJSON_IsObject(netconfNotifications))
        {
            printf("Status JSON is not as expected: netconf-notifications-sent is not an object.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-normal");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-normal is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        
        counter = (int)(severity->valuedouble);
        netconf_counter->normal += (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-warning");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-warning is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->warning += (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-minor");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-minor is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->minor += (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-major");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-major is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->major += (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-critical");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-critical is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->critical += (counter * NETCONF_CONNECTIONS_PER_DEVICE);
    }

    cJSON_Delete(jsonStatus);

    return SR_ERR_OK;
}

int getDeviceCounters(char *containerId, counterAlarms *ves_counter, counterAlarms *netconf_counter)
{
    cJSON *jsonStatus = getDeviceListFromStatusFile();

    cJSON *deviceList = cJSON_GetObjectItemCaseSensitive(jsonStatus, "device-list");
	if (!cJSON_IsArray(deviceList))
	{
		printf("Status JSON is not as expected: device-list is not an object");
		cJSON_Delete(jsonStatus);
		return SR_ERR_OPERATION_FAILED;
	}

    int array_size = cJSON_GetArraySize(deviceList);

    ves_counter->critical = ves_counter->major = ves_counter->minor = ves_counter->warning = ves_counter->normal = 0;
    netconf_counter->critical = netconf_counter->major = netconf_counter->minor = netconf_counter->warning = netconf_counter->normal = 0;

    for (int i=0; i<array_size; ++i)
    {
        cJSON *deviceListEntry = cJSON_GetArrayItem(deviceList, i);

        cJSON *deviceName = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "device-name");
        if (!cJSON_IsString(deviceName))
        {
            printf("Status JSON is not as expected: device-name is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        char *deviceNameString = cJSON_GetStringValue(deviceName);

        if (strcmp(deviceNameString, containerId) != 0)
        {
            continue;
        }

        cJSON *vesNotifications = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "ves-notifications-sent");
        if (!cJSON_IsObject(vesNotifications))
        {
            printf("Status JSON is not as expected: ves-notifications-sent is not an object.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }

        cJSON *severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-normal");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-normal is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        int counter = (int)(severity->valuedouble);
        ves_counter->normal = counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-warning");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-warning is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->warning = counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-minor");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-minor is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->minor = counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-major");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-major is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->major = counter;

        severity = cJSON_GetObjectItemCaseSensitive(vesNotifications, "severity-critical");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-critical is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        ves_counter->critical = counter;

        cJSON *netconfNotifications = cJSON_GetObjectItemCaseSensitive(deviceListEntry, "netconf-notifications-sent");
        if (!cJSON_IsObject(netconfNotifications))
        {
            printf("Status JSON is not as expected: netconf-notifications-sent is not an object.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-normal");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-normal is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        
        counter = (int)(severity->valuedouble);
        netconf_counter->normal = (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-warning");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-warning is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->warning = (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-minor");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-minor is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->minor = (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-major");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-major is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->major = (counter * NETCONF_CONNECTIONS_PER_DEVICE);

        severity = cJSON_GetObjectItemCaseSensitive(netconfNotifications, "severity-critical");
        if (!cJSON_IsNumber(severity))
        {
            printf("Status JSON is not as expected: severity-critical is not a string.");
            cJSON_Delete(jsonStatus);
            return SR_ERR_OPERATION_FAILED;
        }
        counter = (int)(severity->valuedouble);
        netconf_counter->critical = (counter * NETCONF_CONNECTIONS_PER_DEVICE);
    }

    cJSON_Delete(jsonStatus);

    return SR_ERR_OK;
}

int writeSkeletonConfigFile()
{
    cJSON *configObject = cJSON_CreateObject();
    if (configObject == NULL)
    {
        printf("Could not create JSON object: configObject\n");
        return SR_ERR_OPERATION_FAILED;
    }

    cJSON *notificationConfig = cJSON_CreateObject();
    if (notificationConfig == NULL)
    {
        printf("Could not create JSON object: notificationConfig\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }
    cJSON_AddItemToObject(configObject, "notification-config", notificationConfig);

    if (cJSON_AddNumberToObject(notificationConfig, "ves-heartbeat-period", 0) == NULL)
    {
        printf("Could not create JSON object: ves-heartbeat-period\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddTrueToObject(notificationConfig, "is-netconf-available") == NULL)
    {
        printf("Could not create JSON object: is-netconf-available\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddTrueToObject(notificationConfig, "is-ves-available") == NULL)
    {
        printf("Could not create JSON object: is-ves-available\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    cJSON *faultNotificationDelayPeriod = cJSON_CreateArray();
    if (faultNotificationDelayPeriod == NULL)
    {
        printf("Could not create JSON object: faultNotificationDelayPeriod\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
	}
    cJSON_AddItemToObject(notificationConfig, "fault-notification-delay-period", faultNotificationDelayPeriod);

    cJSON *arrayItem = cJSON_CreateNumber(0);
    if (arrayItem == NULL)
    {
        printf("Could not create JSON object: arrayItem\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
	}
    cJSON_AddItemToArray(faultNotificationDelayPeriod, arrayItem);

    cJSON *vesEndPointDetails = cJSON_CreateObject();
    if (vesEndPointDetails == NULL)
    {
        printf("Could not create JSON object: vesEndPointDetails\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }
    cJSON_AddItemToObject(configObject, "ves-endpoint-details", vesEndPointDetails);

    if (cJSON_AddStringToObject(vesEndPointDetails, "ves-endpoint-ip", "172.17.0.1") == NULL)
    {
        printf("Could not create JSON object: ves-endpoint-ip\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddNumberToObject(vesEndPointDetails, "ves-endpoint-port", 30007) == NULL)
    {
        printf("Could not create JSON object: ves-endpoint-port\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddStringToObject(vesEndPointDetails, "ves-endpoint-auth-method", "no-auth") == NULL)
    {
        printf("Could not create JSON object: ves-endpoint-auth-method\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddStringToObject(vesEndPointDetails, "ves-endpoint-username", "") == NULL)
    {
        printf("Could not create JSON object: ves-endpoint-username\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddStringToObject(vesEndPointDetails, "ves-endpoint-password", "") == NULL)
    {
        printf("Could not create JSON object: ves-endpoint-password\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddStringToObject(vesEndPointDetails, "ves-endpoint-certificate", "") == NULL)
    {
        printf("Could not create JSON object: ves-endpoint-certificate\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddFalseToObject(vesEndPointDetails, "ves-registration") == NULL)
    {
        printf("Could not create JSON object: ves-registration\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    cJSON *controllerDetails = cJSON_CreateObject();
    if (controllerDetails == NULL)
    {
        printf("Could not create JSON object: controllerDetails\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }
    cJSON_AddItemToObject(configObject, "controller-details", controllerDetails);

    if (cJSON_AddStringToObject(controllerDetails, "controller-ip", "172.17.0.1") == NULL)
    {
        printf("Could not create JSON object: controller-ip\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddNumberToObject(controllerDetails, "controller-port", 8181) == NULL)
    {
        printf("Could not create JSON object: controller-port\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddNumberToObject(controllerDetails, "netconf-call-home-port", 6666) == NULL)
    {
        printf("Could not create JSON object: netconf-call-home-port\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddStringToObject(controllerDetails, "controller-username", "admin") == NULL)
    {
        printf("Could not create JSON object: controller-username\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddStringToObject(controllerDetails, "controller-password", "admin") == NULL)
    {
        printf("Could not create JSON object: controller-password\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddNumberToObject(configObject, "ssh-connections", 1) == NULL)
    {
        printf("Could not create JSON object: ssh-connections\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddNumberToObject(configObject, "tls-connections", 0) == NULL)
    {
        printf("Could not create JSON object: tls-connections\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    if (cJSON_AddFalseToObject(configObject, "netconf-call-home") == NULL)
    {
        printf("Could not create JSON object: netconf-call-home\n");
        cJSON_Delete(configObject);
        return SR_ERR_OPERATION_FAILED;
    }

    char *config_string = NULL;

    config_string = cJSON_PrintUnformatted(configObject);

    writeConfigFile(config_string);

    if (config_string != NULL)
    {
        free(config_string);
        config_string = NULL;
    }

    if (configObject != NULL)
    {
        cJSON_Delete(configObject);
    }

    return SR_ERR_OK;
}

int getIntFromString(char *string, int def_value)
{
    int rc, value = def_value;
    if (string != NULL)
    {
        rc = sscanf(string, "%d", &value);
        if (rc != 1)
        {
            printf("Could not get the %s! Using the default 0...\n", string);
            value = def_value;
        }
    }
    return value;
}

int     getSshConnectionsFromConfigJson(void)
{
    char *stringConfig = readConfigFileInString();

    if (stringConfig == NULL)
    {
        printf("Could not read JSON configuration file in string.");
        return 0;
    }

    cJSON *jsonConfig = cJSON_Parse(stringConfig);
    if (jsonConfig == NULL)
    {
        free(stringConfig);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
        }
        return SR_ERR_OPERATION_FAILED;
    }
    //we don't need the string anymore
    free(stringConfig);
    stringConfig = NULL;

    cJSON *sshConnections = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ssh-connections");
    if (!cJSON_IsNumber(sshConnections))
    {
        printf("Configuration JSON is not as expected: ssh-connections is not an object");
        cJSON_Delete(jsonConfig);
        return SR_ERR_OPERATION_FAILED;
    }

    int num_of_ssh = (int)(sshConnections->valuedouble);

    cJSON_Delete(jsonConfig);

    return num_of_ssh;
}

int     getTlsConnectionsFromConfigJson(void)
{
    char *stringConfig = readConfigFileInString();

    if (stringConfig == NULL)
    {
        printf("Could not read JSON configuration file in string.");
        return 0;
    }

    cJSON *jsonConfig = cJSON_Parse(stringConfig);
    if (jsonConfig == NULL)
    {
        free(stringConfig);
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Could not parse JSON configuration! Error before: %s\n", error_ptr);
        }
        return SR_ERR_OPERATION_FAILED;
    }
    //we don't need the string anymore
    free(stringConfig);
    stringConfig = NULL;

    cJSON *tlsConnections = cJSON_GetObjectItemCaseSensitive(jsonConfig, "tls-connections");
    if (!cJSON_IsNumber(tlsConnections))
    {
        printf("Configuration JSON is not as expected: ssh-connections is not an object");
        cJSON_Delete(jsonConfig);
        return SR_ERR_OPERATION_FAILED;
    }

    int num_of_tls = (int)(tlsConnections->valuedouble);

    cJSON_Delete(jsonConfig);

    return num_of_tls;
}
