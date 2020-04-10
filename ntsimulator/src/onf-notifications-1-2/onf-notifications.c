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
#include <time.h>
#include <math.h>
#include <sys/time.h>
#include <string.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include "utils.h"

#define LINE_BUFSIZE 128
#define ONF_PROBLEM_NOTIFICATION_NUMBER 10

volatile int exit_application = 0;

static counterAlarms netconf_alarm_counter = {
    .normal = 0,
    .warning = 0,
    .minor = 0,
    .major = 0,
    .critical = 0
};
static counterAlarms ves_alarm_counter= {
    .normal = 0,
    .warning = 0,
    .minor = 0,
    .major = 0,
    .critical = 0
};

struct faultAlarms
{
	char* 		objectIdRef;
	char*		severity;
	char*		problem;
	int			cleared;
};
struct faultAlarms onf_problem_notifications[ONF_PROBLEM_NOTIFICATION_NUMBER] = {
		{.objectIdRef = "052b93e0-d43d-4530-9563-efd832284423",
		.severity = "critical", .problem = "signalIsLost",
		.cleared = 1
		},
		{.objectIdRef = "ac6601e8-f5de-4ce6-9543-6ca0e8aacd10",
		.severity = "minor", .problem = "rslIsExceeded",
		.cleared = 1
		},
		{.objectIdRef = "39df2a10-3e5c-46ca-bef3-8348bc15c6c0",
		.severity = "warning", .problem = "signalIDMismatching",
		.cleared = 1
		},
		{.objectIdRef = "052b93e0-d43d-4530-9563-efd832284423",
		.severity = "critical", .problem = "temperatureIsExceeded",
		.cleared = 1
		},
		{.objectIdRef = "052b93e0-d43d-4530-9563-efd832284423",
		.severity = "major", .problem = "modemIsFaulty",
		.cleared = 1
		},
		{.objectIdRef = "052b93e0-d43d-4530-9563-efd832284423",
		.severity = "warning", .problem = "modulationIsDownshifted",
		.cleared = 1
		},
		{.objectIdRef = "39df2a10-3e5c-46ca-bef3-8348bc15c6c0",
		.severity = "major", .problem = "modemIsFaulty",
		.cleared = 1
		},
		{.objectIdRef = "ac6601e8-f5de-4ce6-9543-6ca0e8aacd10",
		.severity = "critical", .problem = "temperatureIsExceeded",
		.cleared = 1
		},
		{.objectIdRef = "ac6601e8-f5de-4ce6-9543-6ca0e8aacd10",
		.severity = "major", .problem = "modemIsFaulty",
		.cleared = 1
		},
		{.objectIdRef = "ac6601e8-f5de-4ce6-9543-6ca0e8aacd10",
		.severity = "warning", .problem = "modulationIsDownshifted",
		.cleared = 1
		}
};

static int send_dummy_notif(sr_session_ctx_t *sess)
{
	int rc;

    char dateAndTime[256];
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
    sprintf(dateAndTime, "%04d-%02d-%02dT%02d:%02d:%02d.%01dZ",
    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
    tm.tm_hour, tm.tm_min, tm.tm_sec, millisec/100);

    int ran = (int) random_at_most(ONF_PROBLEM_NOTIFICATION_NUMBER - 1);

	static int problemNotificationCounter = 0;

	sr_val_t *vnotif;
	size_t current_num_of_values= 0;

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/microwave-model:problem-notification/counter");
	vnotif[current_num_of_values - 1].type = SR_INT32_T;
	vnotif[current_num_of_values - 1].data.uint32_val = problemNotificationCounter++;

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/microwave-model:problem-notification/time-stamp");
	sr_val_build_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, "%s", dateAndTime);

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/microwave-model:problem-notification/object-id-ref");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, onf_problem_notifications[ran].objectIdRef);

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/microwave-model:problem-notification/problem");	    
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, onf_problem_notifications[ran].problem);

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/microwave-model:problem-notification/severity");	    
	if (onf_problem_notifications[ran].cleared == 1)
    {
    	onf_problem_notifications[ran].cleared = 0;
		sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_ENUM_T, onf_problem_notifications[ran].severity);
    }
    else
    {
    	onf_problem_notifications[ran].cleared = 1;
		sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_ENUM_T, "non-alarmed");
    }

	int isNetconfAvailable = getNetconfAvailableFromConfigJson();

	if (isNetconfAvailable)
	{
		rc = sr_event_notif_send(sess, "/microwave-model:problem-notification", vnotif, current_num_of_values, SR_EV_NOTIF_DEFAULT);
		if (rc != SR_ERR_OK)
		{
			printf("Failed to send notification send_dummy_notif\n");
			return SR_ERR_OPERATION_FAILED;
		}
        if (onf_problem_notifications[ran].cleared == 1)
        {
            netconf_alarm_counter.normal++;
        }
        else
        {
            if (strcmp(onf_problem_notifications[ran].severity, "warning") == 0)
            {
                netconf_alarm_counter.warning++;
            }
            else if (strcmp(onf_problem_notifications[ran].severity, "minor") == 0)
            {
                netconf_alarm_counter.minor++;
            }
            else if (strcmp(onf_problem_notifications[ran].severity, "major") == 0)
            {
                netconf_alarm_counter.major++;
            }
            else if (strcmp(onf_problem_notifications[ran].severity, "critical") == 0)
            {
                netconf_alarm_counter.critical++;
            }
		}
		printf("Successfully sent notification with timestamp=\"%s\"\n", dateAndTime);
	}

    printf("Writing counters to file...\n");
    rc = writeStatusNotificationCounters(ves_alarm_counter, netconf_alarm_counter);
    if (rc != SR_ERR_OK)
    {
        printf("Could not write status to file...\n");
    }

	sr_free_values(vnotif, current_num_of_values);

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
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    int notification_delay_period = 0; //seconds

    setbuf(stdout, NULL);

    /* connect to sysrepo */
    rc = sr_connect("onf_notifications", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);


    while (!exit_application) {
        notification_delay_period = getFaultNotificationDelayPeriodFromConfigJson();

        if (notification_delay_period > 0)
        {
        	send_dummy_notif(session);

            sleep(notification_delay_period);
        }
        else
        {
        	sleep(1);
            // reset the counters when the notifciation delay period is switched back to 0
            netconf_alarm_counter.normal = netconf_alarm_counter.warning = \
            netconf_alarm_counter.minor = netconf_alarm_counter.major = \
            netconf_alarm_counter.critical = 0;
            
            ves_alarm_counter.normal = ves_alarm_counter.warning = \
            ves_alarm_counter.minor = ves_alarm_counter.major = \
            ves_alarm_counter.critical = 0;
        }

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
    printf("Error encountered. Exiting...");
    return rc;
}




