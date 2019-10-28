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

void 	getCurrentDateAndTime(char *date_and_time);
int 	getSecondsFromLastQuarterInterval(void);
int 	getSecondsFromLastDayInterval(void);
void 	getPreviousQuarterInterval(int number_of_intervals, char *date_and_time);
void 	getPreviousDayPmTimestamp(int number_of_intervals, char *date_and_time);
long int getMicrosecondsSinceEpoch(void);

cJSON*	vesCreateCommonEventHeader(void);
cJSON*	vesCreateHeartbeatFields(int heartbeat_interval);

char* 	readConfigFileInString(void);
void 	writeConfigFile(char *config);

int 	getFaultNotificationDelayPeriodFromConfigJson(void);
int 	getVesHeartbeatPeriodFromConfigJson(void);
char* 	getVesAuthMethodFromConfigJson(void);
char* 	getVesIpv4FromConfigJson(void);
int 	getVesPortFromConfigJson(void);


#endif /* EXAMPLES_NTSIMULATOR_UTILS_H_ */
