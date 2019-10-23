/*
 * o-ran-notifications.c
 *
 *  Created on: Oct 23, 2019
 *      Author: parallels
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include "utils.h"

#define LINE_BUFSIZE 128
#define ORAN_FAULT_ALARMS_NUMBER 10
#define AFFECTED_OBJECTS_MAX_NUMBER 100

volatile int exit_application = 0;

struct faultAlarms
{
	int 		faultId;
	char* 		faultSource;
	int 		cleared;
	char*		faultSeverity;
	char*		faultText;
	char* 		affectedObjects[AFFECTED_OBJECTS_MAX_NUMBER];
};
struct faultAlarms oran_fault_alarms[ORAN_FAULT_ALARMS_NUMBER] = {
		{.faultId = 1, .faultSource = "jknsdfnui", .affectedObjects = {"akddconoj", "asodmnjvf", "roiemfkmods"}, .cleared = 1, .faultSeverity = "MAJOR", .faultText = "sdnjosopnojnsd"},
		{.faultId = 2, .faultSource = "onascokjnasc", .affectedObjects = {"sdouvncsjdfv13", "asjdn13ejlncd4"}, .cleared = 1, .faultSeverity = "WARNING", .faultText = "4pionfcsofn42on"},
		{.faultId = 3, .faultSource = "asonxpkn", .affectedObjects = {"0j4fiwef320fd", "sdlvkmsdv-9023"}, .cleared = 1, .faultSeverity = "CRITICAL", .faultText = "sdjnonj32onjsa23"},
		{.faultId = 4, .faultSource = "asnjcpkd", .affectedObjects = {"0j4fiwef320fd", "sdlvkmsdv-9023", "laksmdklmdas21"}, .cleared = 1, .faultSeverity = "MINOR", .faultText = "asdjln12osa453"},
		{.faultId = 5, .faultSource = "dskmfl", .affectedObjects = {"sdkm31wdlk"}, .cleared = 1, .faultSeverity = "MAJOR", .faultText = "dknovrf34ekl"},
		{.faultId = 6, .faultSource = "dsllkje232kl", .affectedObjects = {"sFKOM24KLMerw"}, .cleared = 1, .faultSeverity = "MAJOR", .faultText = "frpkm24k lsd	kmewfpm"},
		{.faultId = 7, .faultSource = "fvkdlsfjnwej23kloe", .affectedObjects = {"fvkm24km", "sdfk23d", "kmdfkmo32", "wekl2332"}, .cleared = 1, .faultSeverity = "WARNING", .faultText = "dsm 2d 32j sdfmr32"},
		{.faultId = 8, .faultSource = "dkom32", .affectedObjects = {"kmsdfkpm23ds", "sdmkp32"}, .cleared = 1, .faultSeverity = "CRITICAL", .faultText = "dsonj32 don32 mdson32pk654"},
		{.faultId = 9, .faultSource = "weflm3", .affectedObjects = {"klklm32kl3", "dsfln234poewj23-", "spmd32k"}, .cleared = 1, .faultSeverity = "MINOR", .faultText = "dsflknjwej32"},
		{.faultId = 10, .faultSource = "fweiunvfrem32", .affectedObjects = {"sfkm23klsdf2343"}, .cleared = 1, .faultSeverity = "MAJOR", .faultText = "dfskjnl4j dsfknl2 fodn54 65k"}
};

static long random_at_most(long max) {
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

static int send_dummy_notif_file_mgmt(sr_session_ctx_t *sess)
{
	int rc;

	sr_val_t *vnotif;
	size_t current_num_of_values= 0;

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-file-management:file-upload-notification/local-logical-file-path");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, "odsanzucjsdoj");

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-file-management:file-upload-notification/remote-file-path");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, "jsdknvjnkfd");

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-file-management:file-upload-notification/status");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_ENUM_T, "SUCCESS");

	rc = sr_event_notif_send(sess, "/o-ran-file-management:file-upload-notification", vnotif, current_num_of_values, SR_EV_NOTIF_DEFAULT);
	if (rc != SR_ERR_OK) {
		printf("Failed to send notification send_dummy_notif_file_mgmt\n");
		return SR_ERR_OPERATION_FAILED;
	}

	printf("Successfully sent notification...\n");

	return SR_ERR_OK;
}

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

    int ran = (int) random_at_most(ORAN_FAULT_ALARMS_NUMBER - 1);

    if (oran_fault_alarms[ran].cleared == 1)
    {
    	oran_fault_alarms[ran].cleared = 0;
    }
    else
    {
    	oran_fault_alarms[ran].cleared = 1;
    }

	sr_val_t *vnotif;
	size_t current_num_of_values= 0;

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-fm:alarm-notif/fault-id");
	vnotif[current_num_of_values - 1].type = SR_UINT16_T;
	vnotif[current_num_of_values - 1].data.uint16_val = oran_fault_alarms[ran].faultId;

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-fm:alarm-notif/fault-source");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, oran_fault_alarms[ran].faultSource);

	for (int  i = 0; i < AFFECTED_OBJECTS_MAX_NUMBER; ++i)
	{
		char path[400];
		if (oran_fault_alarms[ran].affectedObjects[i] == NULL)
		{
			break;
		}

		sprintf(path, "/o-ran-fm:alarm-notif/affected-objects[name='%s']", oran_fault_alarms[ran].affectedObjects[i]);

		CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

		sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", path);
		vnotif[current_num_of_values - 1].type = SR_LIST_T;
	}

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-fm:alarm-notif/fault-severity");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_ENUM_T, oran_fault_alarms[ran].faultSeverity);

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-fm:alarm-notif/is-cleared");
	vnotif[current_num_of_values - 1].type = SR_BOOL_T;
	vnotif[current_num_of_values - 1].data.bool_val = oran_fault_alarms[ran].cleared;

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-fm:alarm-notif/fault-text");
	sr_val_set_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, oran_fault_alarms[ran].faultText);

	CREATE_NEW_VALUE(rc, vnotif, current_num_of_values);

	sr_val_build_xpath(&vnotif[current_num_of_values - 1], "%s", "/o-ran-fm:alarm-notif/event-time");
	sr_val_build_str_data(&vnotif[current_num_of_values - 1], SR_STRING_T, "%s", dateAndTime);

	rc = sr_event_notif_send(sess, "/o-ran-fm:alarm-notif", vnotif, current_num_of_values, SR_EV_NOTIF_DEFAULT);
	if (rc != SR_ERR_OK) {
		printf("Failed to send notification send_dummy_notif\n");
		return SR_ERR_OPERATION_FAILED;
	}

	printf("Successfully sent notification with timestamp=\"%s\"\n", dateAndTime);

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
    rc = sr_connect("oran_notifications", SR_CONN_DEFAULT, &connection);
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
        FILE * fp;
		char * line = NULL;
		size_t len = 0;
		ssize_t read;

        char script[200];
		sprintf(script, "%s/gen.notif", getenv("SCRIPTS_DIR"));

        fp = fopen(script, "r");
        if (fp == NULL)
        {
        	printf("Could not read the notification-delay-period from path=%s\n", script);
            exit(EXIT_FAILURE);
        }

		while ((read = getline(&line, &len, fp)) != -1) {
			sscanf(line, "%d", &notification_delay_period);
			break;
		}

		fclose(fp);
		if (line)
		{
			free(line);
		}

        if (notification_delay_period > 0)
        {
        	send_dummy_notif(session);
//        	send_dummy_notif_file_mgmt(session);

            sleep(notification_delay_period);
        }
        else
        {
        	sleep(1);
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




