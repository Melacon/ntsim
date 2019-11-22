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

long random_at_most(long max) {
  unsigned long
    // max <= RAND_MAX < ULONG_MAX, so this is okay.
    num_bins = (unsigned long) max + 1,
    num_rand = (unsigned long) RAND_MAX + 1,
    bin_size = num_rand / num_bins,
    defect   = num_rand % num_bins;

  long x;
  do {
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
	struct tm tm = *localtime(&t);
	struct timeval tv;
	long int useconds;

	gettimeofday(&tv, NULL);
	useconds = t*1000 + tv.tv_usec; //add the microseconds to the seconds

	return useconds;
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

	cJSON *notifDetails = cJSON_GetObjectItemCaseSensitive(jsonConfig, "notification-config");
	if (!cJSON_IsObject(notifDetails))
	{
		printf("Configuration JSON is not as expected: notification-config is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	cJSON *isNetconfAvailable = cJSON_GetObjectItemCaseSensitive(notifDetails, "is-netconf-available");
	if (!cJSON_IsBool(isNetconfAvailable))
	{
		printf("Configuration JSON is not as expected: is-netconf-available is not an object");
		free(jsonConfig);
		return SR_ERR_OPERATION_FAILED;
	}

	int is_netconf_available = (cJSON_IsTrue(isNetconfAvailable)) ? TRUE : FALSE;

	free(jsonConfig);

	return is_netconf_available;
}
