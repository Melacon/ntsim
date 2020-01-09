/*
 * utils.h
 *
 *  Created on: Feb 19, 2019
 *      Author: parallels
 */

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

int 	getFaultNotificationDelayPeriodFromConfigJson(void);
int 	getVesHeartbeatPeriodFromConfigJson(void);
char* 	getVesAuthMethodFromConfigJson(void);
char* 	getVesIpFromConfigJson(void);
int 	getVesPortFromConfigJson(void);
int 	getVesRegistrationFromConfigJson(void);
int 	getNetconfAvailableFromConfigJson(void);
int 	getVesAvailableFromConfigJson(void);

void	generateRandomMacAddress(char *mac_address);

#endif /* EXAMPLES_NTSIMULATOR_UTILS_H_ */
