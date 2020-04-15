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

#ifndef EXAMPLES_NTSIMULATOR_UTILS_H_
#define EXAMPLES_NTSIMULATOR_UTILS_H_

#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <cjson/cJSON.h>

#define TRUE 1
#define FALSE 0

#define NETCONF_CONNECTIONS_PER_DEVICE 10

#define PREPARE_ADD_NEW_VALUE(v, num) 	{\
										num++;\
										}

#define CREATE_NEW_VALUE(rc, v, num) 	{\
										rc = sr_realloc_values(num, num+1, &v);\
										if (SR_ERR_OK != rc) {\
											return rc;\
										}\
										num++;\
										}

typedef struct
{
	int normal;
	int warning;
	int minor;
	int major;
	int critical;
} counterAlarms;

void 		set_curl_common_info_ves(CURL *curl);

long 		random_at_most(long max);
void 		getCurrentDateAndTime(char *date_and_time);
int 		getSecondsFromLastQuarterInterval(void);
int 		getSecondsFromLastDayInterval(void);
void 		getPreviousQuarterInterval(int number_of_intervals, char *date_and_time);
void 		getPreviousDayPmTimestamp(int number_of_intervals, char *date_and_time);
long int 	getMicrosecondsSinceEpoch(void);
void 		prepare_ves_message_curl(CURL *curl);

cJSON*	vesCreateCommonEventHeader(char *domain, char *event_type, char *source_name, int seq_id);
cJSON*	vesCreateHeartbeatFields(int heartbeat_interval);
cJSON*	vesCreatePnfRegistrationFields(int port, bool is_tls);
cJSON*	vesCreateFaultFields(char *alarm_condition, char *alarm_object, char *severity, char *date_time, char *specific_problem);

char* 	readConfigFileInString(void);
void 	writeConfigFile(char *config);

int 	getFaultNotificationDelayPeriodFromConfigJson(int *period_array, int *count);
int 	getVesHeartbeatPeriodFromConfigJson(void);
char* 	getVesAuthMethodFromConfigJson(void);
char* 	getVesIpFromConfigJson(void);
int 	getVesPortFromConfigJson(void);
int 	getVesRegistrationFromConfigJson(void);
int 	getNetconfAvailableFromConfigJson(void);
int 	getVesAvailableFromConfigJson(void);

void	generateRandomMacAddress(char *mac_address);

int 	writeSkeletonStatusFile(void);
char* 	readStatusFileInString(void);

int     writeStatusNotificationCounters(counterAlarms ves_counter, counterAlarms netconf_counter);
void    writeStatusFile(char *status);
int     removeDeviceEntryFromStatusFile(char *deviceName);

cJSON*  getDeviceListFromStatusFile(void);
int     compute_notifications_count(counterAlarms *ves_counter, counterAlarms *netconf_counter);
int     getDeviceCounters(char *containerId, counterAlarms *ves_counter, counterAlarms *netconf_counter);

#endif /* EXAMPLES_NTSIMULATOR_UTILS_H_ */
