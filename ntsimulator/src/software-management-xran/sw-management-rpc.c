/**
 * @file sw-management-rpc.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Example usage of RPC API.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <pthread.h>

#include "sysrepo.h"
#include "sysrepo/values.h"

#include "utils.h"

#define LINE_BUFSIZE 128

volatile int exit_application = 0;

pthread_mutex_t lock;

static int sw_download_error_count, sw_install_error_count, sw_activate_error_count;

void call_software_management_script(char *script_name)
{
    char line[LINE_BUFSIZE];
	int linenr;
	FILE *pipe;

	/* Get a pipe where the output from the scripts comes in */
	char script[200];
	sprintf(script, "/opt/dev/%s", script_name);

	pipe = popen(script, "r");
	if (pipe == NULL) {  /* check for errors */
		printf("Could not open script.\n");
		return;        /* return with exit code indicating error */
	}

	/* Read script output from the pipe line by line */
	linenr = 1;
	while (fgets(line, LINE_BUFSIZE, pipe) != NULL) {
		printf("Script output line %d: %s", linenr, line);
		++linenr;
	}

	/* Once here, out of the loop, the script has ended. */
	pclose(pipe); /* Close the pipe */
	return;     /* return with exit code indicating success. */
}

struct sw_download_struct
{
    sr_session_ctx_t *sess;
    char *filename;
};

void* sw_download_notification_send(void *arguments)
{
    // create the values to be sent in the notification
    struct sw_download_struct *args = (struct sw_download_struct *)arguments;
    int rc = SR_ERR_OK;

    sw_download_error_count++;

    sr_val_t *notif = NULL;
    size_t current_num_of_values_notif = 0;

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

    char *trunc_filename;
    trunc_filename = strrchr(args->filename, '/');

    sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:download-event/file-name");
    if (trunc_filename != NULL)
    {
        sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_STRING_T, trunc_filename + 1);

        if (strcmp(trunc_filename+1, "reset") == 0)
        {
            call_software_management_script("edit-config-demo-start.sh");
        }
        else
        {
            call_software_management_script("edit-config-after-download.sh");
        }
    }
    else
    {
        sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_STRING_T, args->filename);
        if (strcmp(args->filename, "reset") == 0)
        {
            call_software_management_script("edit-config-demo-start.sh");
        }
        else
        {
            call_software_management_script("edit-config-after-download.sh");
        }
    }

    if (args->filename != NULL)
    {
        free(args->filename);
    }

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

	sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:download-event/status");
    //every 5 RPCs we send an error
    if (sw_download_error_count % 5 == 0)
    {
	    sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_ENUM_T, "AUTHENTICATION_ERROR");
    }
    else
    {
        sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_ENUM_T, "COMPLETED");
    }
    

    // wait 5 seconds before sending the notification
    sleep(5);

    /* send notification for event_notif_sub(_tree)_example */
    printf(">>> Sending event notification for '/xran-software-management:download-event'...\n");
    rc = sr_event_notif_send(args->sess, "/xran-software-management:download-event", notif, current_num_of_values_notif, SR_EV_NOTIF_DEFAULT);
    if (SR_ERR_NOT_FOUND == rc) {
        printf("No application subscribed for '/xran-software-management:download-event', skipping.\n");
        rc = SR_ERR_OK;
    }
    sr_free_values(notif, current_num_of_values_notif);

    return NULL;
}

struct sw_install_struct
{
    sr_session_ctx_t *sess;
    char *slot_name;
};

void* sw_install_notification_send(void *arguments)
{
    // create the values to be sent in the notification
    struct sw_install_struct *args = (struct sw_install_struct *)arguments;
    int rc = SR_ERR_OK;
    sw_install_error_count++;

    sr_val_t *notif = NULL;
    size_t current_num_of_values_notif = 0;

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

    sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:install-event/slot-name");
    sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_STRING_T, args->slot_name);

    if (args->slot_name != NULL)
    {
        free(args->slot_name);
    }

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

	sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:install-event/status");

	//every 5 RPCs we send an error
    if (sw_install_error_count % 5 == 0)
    {
	    sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_ENUM_T, "INTEGRITY_ERROR");
    }
    else
    {
        sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_ENUM_T, "COMPLETED");
    }

    // wait 5 seconds before sending the notification
    sleep(5);

    /* send notification for event_notif_sub(_tree)_example */
    printf(">>> Sending event notification for '/xran-software-management:install-event'...\n");
    rc = sr_event_notif_send(args->sess, "/xran-software-management:install-event", notif, current_num_of_values_notif, SR_EV_NOTIF_DEFAULT);
    if (SR_ERR_NOT_FOUND == rc) {
        printf("No application subscribed for '/xran-software-management:install-event', skipping.\n");
        rc = SR_ERR_OK;
    }
    sr_free_values(notif, current_num_of_values_notif);

    return NULL;
}

struct sw_activate_struct
{
    sr_session_ctx_t *sess;
    char *slot_name;
};

void* sw_activate_notification_send(void *arguments)
{
    // create the values to be sent in the notification
    struct sw_activate_struct *args = (struct sw_activate_struct *)arguments;
    int rc = SR_ERR_OK;
    sw_activate_error_count++;

    sr_val_t *notif = NULL;
    size_t current_num_of_values_notif = 0;

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

    sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:activation-event/slot-name");
    sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_STRING_T, args->slot_name);

    if (args->slot_name != NULL)
    {
        free(args->slot_name);
    }

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

	sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:activation-event/status");
	//every 5 RPCs we send an error
    if (sw_activate_error_count % 5 == 0)
    {
	    sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_ENUM_T, "APPLICATION_ERROR");
    }
    else
    {
        sr_val_set_str_data(&notif[current_num_of_values_notif - 1], SR_ENUM_T, "COMPLETED");

        call_software_management_script("edit-config-after-activate.sh");
    }

    CREATE_NEW_VALUE(rc, notif, current_num_of_values_notif);

	sr_val_build_xpath(&notif[current_num_of_values_notif - 1], "%s", "/xran-software-management:activation-event/return-code");
    notif[current_num_of_values_notif - 1].type = SR_UINT8_T;
    notif[current_num_of_values_notif - 1].data.uint8_val = 200;

    // wait 5 seconds before sending the notification
    sleep(5);

    /* send notification for event_notif_sub(_tree)_example */
    printf(">>> Sending event notification for '/xran-software-management:activation-event'...\n");
    rc = sr_event_notif_send(args->sess, "/xran-software-management:activation-event", notif, current_num_of_values_notif, SR_EV_NOTIF_DEFAULT);
    if (SR_ERR_NOT_FOUND == rc) {
        printf("No application subscribed for '/xran-software-management:activation-event', skipping.\n");
        rc = SR_ERR_OK;
    }
    sr_free_values(notif, current_num_of_values_notif);

    return NULL;
}

static int
sw_download_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
       sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;

    /**
     * Here you would actually run the operation against the provided input values
     * and obtained the output values.
     */

    /* allocate output values */
    rc = sr_new_values(2, output);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(&(*output)[0], "/xran-software-management:software-download/status");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[0].type = SR_ENUM_T;
    (*output)[0].data.enum_val = "STARTED";

    rc = sr_val_set_xpath(&(*output)[1], "/xran-software-management:software-download/notification-timeout");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[1].type = SR_INT32_T;
    (*output)[1].data.int32_val = 10;

    /* inform sysrepo about the number of output values */
    *output_cnt = 2;

    struct sw_download_struct *args = (struct sw_download_struct *)malloc(sizeof(struct sw_download_struct));
    args->sess = session;
    args->filename = strdup(input[0].data.string_val);

    pthread_t sw_download_thread;
	if(pthread_create(&sw_download_thread, NULL, &sw_download_notification_send, (void *)args))
	{
		fprintf(stderr, "Could not create thread for SW Download thread\n");
		return SR_ERR_OPERATION_FAILED;
	}

    /**
     * Do not deallocate input values!
     * They will get freed automatically by sysrepo.
     */
    return rc;
}

static int
sw_install_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
       sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;

    /**
     * Here you would actually run the operation against the provided input values
     * and obtained the output values.
     */

    /* allocate output values */
    rc = sr_new_values(1, output);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(&(*output)[0], "/xran-software-management:software-install/status");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[0].type = SR_ENUM_T;
    (*output)[0].data.enum_val = "STARTED";

    /* inform sysrepo about the number of output values */
    *output_cnt = 1;

    struct sw_install_struct *args = (struct sw_install_struct *)malloc(sizeof(struct sw_install_struct));
    args->sess = session;
    args->slot_name = strdup(input[0].data.string_val);

    pthread_t sw_install_thread;
	if(pthread_create(&sw_install_thread, NULL, &sw_install_notification_send, (void *)args))
	{
		fprintf(stderr, "Could not create thread for SW Install thread\n");
		return SR_ERR_OPERATION_FAILED;
	}

    /**
     * Do not deallocate input values!
     * They will get freed automatically by sysrepo.
     */
    return rc;
}

static int
sw_activate_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
       sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;

    /**
     * Here you would actually run the operation against the provided input values
     * and obtained the output values.
     */

    /* allocate output values */
    rc = sr_new_values(2, output);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(&(*output)[0], "/xran-software-management:software-activate/status");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[0].type = SR_ENUM_T;
    (*output)[0].data.enum_val = "STARTED";

    rc = sr_val_set_xpath(&(*output)[1], "/xran-software-management:software-activate/notification-timeout");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*output)[1].type = SR_INT32_T;
    (*output)[1].data.int32_val = 10;

    /* inform sysrepo about the number of output values */
    *output_cnt = 2;

    struct sw_activate_struct *args = (struct sw_activate_struct *)malloc(sizeof(struct sw_activate_struct));
    args->sess = session;
    args->slot_name = strdup(input[0].data.string_val);

    pthread_t sw_activate_thread;
	if(pthread_create(&sw_activate_thread, NULL, &sw_activate_notification_send, (void *)args))
	{
		fprintf(stderr, "Could not create thread for SW Activate thread\n");
		return SR_ERR_OPERATION_FAILED;
	}

    /**
     * Do not deallocate input values!
     * They will get freed automatically by sysrepo.
     */
    return rc;
}

static void
sigint_handler(int signum)
{
    exit_application = 1;
}

static int
rpc_handler(sr_session_ctx_t *session)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* subscribe for handling software-download RPC */
    rc = sr_rpc_subscribe(session, "/xran-software-management:software-download", sw_download_rpc_cb,
            (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_rpc_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* subscribe for handling software-install RPC */
    rc = sr_rpc_subscribe(session, "/xran-software-management:software-install", sw_install_rpc_cb,
            (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_rpc_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

        /* subscribe for handling software-activate RPC */
    rc = sr_rpc_subscribe(session, "/xran-software-management:software-activate", sw_activate_rpc_cb,
            (void *)session, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_rpc_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    printf("\n\n ========== SUBSCRIBED FOR HANDLING RPC ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(session, subscription);
    }
    return rc;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    setbuf(stdout, NULL);

    if (pthread_mutex_init(&lock, NULL) != 0)
	{
		printf("Mutex init failed...\n");
		goto cleanup;
	}

    /* connect to sysrepo */
    rc = sr_connect("sw_management_rpc_app", SR_CONN_DEFAULT, &connection);
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

    /* run as a RPC handler */
    printf("This application will be an RPC handler for 'software-download' operation of 'xran-software-management'.\n");
    rc = rpc_handler(session);

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}
