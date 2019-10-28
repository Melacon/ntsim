/*
 * utils.c
 *
 *  Created on: Feb 19, 2019
 *      Author: parallels
 */

#include "utils.h"

#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>

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
	struct tm tm = *localtime(&t);
	struct timeval tv;
	long int useconds;

	gettimeofday(&tv, NULL);
	useconds = t*1000 + tv.tv_usec; //add the microseconds to the seconds

	return useconds;
}

cJSON*	vesCreateCommonEventHeader(void)
{
	static int sequence_number = 0;
	char dateAndTime[50];
	getCurrentDateAndTime(dateAndTime);

    char hostname[100];
    sprintf(hostname, "%s", getenv("HOSTNAME"));

	long int useconds = getMicrosecondsSinceEpoch;

	cJSON *commonEventHeader = cJSON_CreateObject();
	if (commonEventHeader == NULL)
	{
		printf("Could not create JSON object: commonEventHeader\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "domain", "heartbeat") == NULL)
	{
		printf("Could not create JSON object: domain\n");
		return NULL;
	}

	char eventId[200];
	sprintf(eventId, "%s_%s", hostname, dateAndTime);

	if (cJSON_AddStringToObject(commonEventHeader, "eventId", eventId) == NULL)
	{
		printf("Could not create JSON object: eventId\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "eventName", "heartbeat_Controller") == NULL)
	{
		printf("Could not create JSON object: eventName\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "eventType", "Controller") == NULL)
	{
		printf("Could not create JSON object: eventType\n");
		return NULL;
	}

	if (cJSON_AddNumberToObject(commonEventHeader, "sequence", (double)(sequence_number++)) == NULL)
	{
		printf("Could not create JSON object: sequence\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "priority", "Low") == NULL)
	{
		printf("Could not create JSON object: priority\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "reportingEntityId", "") == NULL)
	{
		printf("Could not create JSON object: reportingEntityId\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "reportingEntityName", hostname) == NULL)
	{
		printf("Could not create JSON object: reportingEntityName\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "sourceId", "") == NULL)
	{
		printf("Could not create JSON object: sourceId\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "sourceName", hostname) == NULL)
	{
		printf("Could not create JSON object: sourceName\n");
		return NULL;
	}

	if (cJSON_AddNumberToObject(commonEventHeader, "startEpochMicrosec", (double)(useconds)) == NULL)
	{
		printf("Could not create JSON object: startEpochMicrosec\n");
		return NULL;
	}

	if (cJSON_AddNumberToObject(commonEventHeader, "lastEpochMicrosec", (double)(useconds)) == NULL)
	{
		printf("Could not create JSON object: lastEpochMicrosec\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "nfNamingCode", "sdn controller") == NULL)
	{
		printf("Could not create JSON object: nfNamingCode\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "nfVendorName", "sdn") == NULL)
	{
		printf("Could not create JSON object: nfVendorName\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "timeZoneOffset", "+00:00") == NULL)
	{
		printf("Could not create JSON object: timeZoneOffset\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "version", "4.0.1") == NULL)
	{
		printf("Could not create JSON object: version\n");
		return NULL;
	}

	if (cJSON_AddStringToObject(commonEventHeader, "vesEventListenerVersion", "7.0.1") == NULL)
	{
		printf("Could not create JSON object: vesEventListenerVersion\n");
		return NULL;
	}

	return commonEventHeader;
}

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
		return NULL;
	}

	if (cJSON_AddNumberToObject(heartbeatFields, "heartbeatInterval", (double)(heartbeat_interval)) == NULL)
	{
		printf("Could not create JSON object: heartbeatInterval\n");
		return NULL;
	}

	cJSON *additionalFields = cJSON_CreateObject();
	if (additionalFields == NULL)
	{
		printf("Could not create JSON object: additionalFields\n");
		return NULL;
	}
	cJSON_AddItemToObject(heartbeatFields, "additionalFields", additionalFields);

	if (cJSON_AddStringToObject(additionalFields, "eventTime", dateAndTime) == NULL)
	{
		printf("Could not create JSON object: eventTime\n");
		return NULL;
	}

	return heartbeatFields;
}

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
	char * buffer = 0;
	long length;
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

int 	getFaultNotificationDelayPeriodFromConfigJson(void)
{
	char *stringConfig = readConfigFileInString();
	int notificationDelay = 0;

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
		printf("Configuration JSON is not as expected: fault-notification-delay-period is not a number");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	notificationDelay = (int)(faultNotifDelay->valuedouble);

	free(jsonConfig);

	return notificationDelay;
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
		printf("Configuration JSON is not as expected: ves-heartbeat-period is not a number");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	vesHeartbeat = (int)(vesHeartbeatPeriod->valuedouble);

	free(jsonConfig);

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
		return SR_ERR_OPERATION_FAILED;
	}
	//we don't need the string anymore
	free(stringConfig);

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesAuthMethod = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-auth-method");
	if (!cJSON_IsString(vesAuthMethod))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-auth-method is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	char *auth_method_string = strdup(cJSON_GetStringValue(vesAuthMethod));

	free(jsonConfig);

	return auth_method_string;
}

/*
 * Dynamically allocated memory;
 * Caller needs to free the memory after it uses the value.
 *
*/
char* 	getVesIpv4FromConfigJson(void)
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

	cJSON *vesDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "ves-endpoint-details");
	if (!cJSON_IsObject(vesDetails))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-details is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *vesIpv4 = cJSON_GetObjectItemCaseSensitive(vesDetails, "ves-endpoint-ipv4");
	if (!cJSON_IsString(vesIpv4))
	{
		printf("Configuration JSON is not as expected: ves-endpoint-ipv4 is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	char *ves_ipv4 = strdup(cJSON_GetStringValue(vesIpv4));

	free(jsonConfig);

	return ves_ipv4;
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
		printf("Configuration JSON is not as expected: ves-endpoint-port is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	int port = (int)(vesPort->valuedouble);

	free(jsonConfig);

	return port;
}
