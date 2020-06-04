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
#include <cjson/cJSON.h>
#include <string.h>
#include <assert.h>

#include "sysrepo.h"
#include "sysrepo/values.h"
#include "libyang/libyang.h"

#include "utils.h"

#define EMEM printf("Memory allocation failed (%s:%d)", __FILE__, __LINE__);

static int op_set_srval(struct lyd_node *node, char *path, int dup, sr_val_t *val, char **val_buf)
{
    uint32_t i;
    struct lyd_node_leaf_list *leaf;
    const char *str;

    if (!dup) {
        assert(val_buf);
        (*val_buf) = NULL;
    }

    if (!dup) {
        val->xpath = path;
    } else {
        sr_val_set_xpath(val, path);
    }
    val->dflt = 0;
    val->data.int64_val = 0;

    switch (node->schema->nodetype) {
    case LYS_CONTAINER:
        val->type = ((struct lys_node_container *)node->schema)->presence ? SR_CONTAINER_PRESENCE_T : SR_CONTAINER_T;
        break;
    case LYS_LIST:
        val->type = SR_LIST_T;
        break;
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (struct lyd_node_leaf_list *)node;
settype:
        switch (leaf->value_type) {
        case LY_TYPE_BINARY:
            val->type = SR_BINARY_T;
            str = leaf->value.binary;
            if (dup) {
                sr_val_set_str_data(val, val->type, str);
            } else {
                val->data.string_val = (char *)str;
            }
            if (NULL == val->data.binary_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_BITS:
            val->type = SR_BITS_T;
            str = leaf->value_str;
            if (dup) {
                sr_val_set_str_data(val, val->type, str);
            } else {
                val->data.string_val = (char *)str;
            }
            break;
        case LY_TYPE_BOOL:
            val->type = SR_BOOL_T;
            val->data.bool_val = leaf->value.bln;
            break;
        case LY_TYPE_DEC64:
            val->type = SR_DECIMAL64_T;
            val->data.decimal64_val = (double)leaf->value.dec64;
            for (i = 0; i < ((struct lys_node_leaf *)leaf->schema)->type.info.dec64.dig; i++) {
                /* shift decimal point */
                val->data.decimal64_val *= 0.1;
            }
            break;
        case LY_TYPE_EMPTY:
            val->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            val->type = SR_ENUM_T;
            str = leaf->value.enm->name;
            if (dup) {
                sr_val_set_str_data(val, val->type, str);
            } else {
                val->data.string_val = (char *)str;
            }
            if (NULL == val->data.enum_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_IDENT:
            val->type = SR_IDENTITYREF_T;

            str = malloc(strlen(lys_main_module(leaf->value.ident->module)->name) + 1 + strlen(leaf->value.ident->name) + 1);
            if (NULL == str) {
                EMEM;
                return -1;
            }
            sprintf((char *)str, "%s:%s", lys_main_module(leaf->value.ident->module)->name, leaf->value.ident->name);
            val->data.identityref_val = (char *)str;
            if (!dup) {
                (*val_buf) = (char *)str;
            }
            break;
        case LY_TYPE_INST:
            val->type = SR_INSTANCEID_T;
            if (dup) {
                sr_val_set_str_data(val, val->type, leaf->value_str);
            } else {
                val->data.string_val = (char *)leaf->value_str;
            }
            break;
        case LY_TYPE_STRING:
            val->type = SR_STRING_T;
            str = leaf->value.string;
            if (dup) {
                sr_val_set_str_data(val, val->type, str);
            } else {
                val->data.string_val = (char *)str;
            }
            if (NULL == val->data.string_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_INT8:
            val->type = SR_INT8_T;
            val->data.int8_val = leaf->value.int8;
            break;
        case LY_TYPE_UINT8:
            val->type = SR_UINT8_T;
            val->data.uint8_val = leaf->value.uint8;
            break;
        case LY_TYPE_INT16:
            val->type = SR_INT16_T;
            val->data.int16_val = leaf->value.int16;
            break;
        case LY_TYPE_UINT16:
            val->type = SR_UINT16_T;
            val->data.uint16_val = leaf->value.uint16;
            break;
        case LY_TYPE_INT32:
            val->type = SR_INT32_T;
            val->data.int32_val = leaf->value.int32;
            break;
        case LY_TYPE_UINT32:
            val->type = SR_UINT32_T;
            val->data.uint32_val = leaf->value.uint32;
            break;
        case LY_TYPE_INT64:
            val->type = SR_INT64_T;
            val->data.int64_val = leaf->value.int64;
            break;
        case LY_TYPE_UINT64:
            val->type = SR_UINT64_T;
            val->data.uint64_val = leaf->value.uint64;
            break;
        case LY_TYPE_LEAFREF:
            leaf = (struct lyd_node_leaf_list *)leaf->value.leafref;
            goto settype;
        default:
            //LY_DERIVED, LY_UNION
            val->type = SR_UNKNOWN_T;
            break;
        }
        break;
    default:
        val->type = SR_UNKNOWN_T;
        break;
    }

    return 0;
}

static int op_add_srval(sr_val_t **values, size_t *values_cnt, struct lyd_node *node)
{
    char *path, *buf = NULL;
    int ret;

    if (sr_realloc_values(*values_cnt, *values_cnt + 1, values) != SR_ERR_OK) {
        return -1;
    }
    ++(*values_cnt);

    path = lyd_path(node);
    ret = op_set_srval(node, path, 1, &(*values)[*values_cnt - 1], &buf);
    free(path);
    free(buf);

    return ret;
}


static int send_dummy_notif(sr_session_ctx_t *sess, const char *module_name, const char *notif_object)
{
	int rc = SR_ERR_OK;

    struct ly_ctx *ctx = NULL;
    struct lyd_node *data = NULL, *iter = NULL;
    sr_schema_t *schemas = NULL;
    size_t schema_cnt = 0;
    sr_val_t *vnotif = NULL;
	size_t num_values= 0;

    ctx = ly_ctx_new("/etc/sysrepo/yang", LY_CTX_ALLIMPLEMENTED);
    if (!ctx) 
    {
       printf("Creating context failed...\n");
       return SR_ERR_OPERATION_FAILED;
    }

    rc = sr_list_schemas(sess, &schemas, &schema_cnt);
    if (rc != SR_ERR_OK)
    {
        printf("Could not list the schemas from the sysrepo session...\n");
        return SR_ERR_OPERATION_FAILED;
    }

    const char *schema_path = NULL;

    for (size_t i = 0; i < schema_cnt; i++) 
    {
        schema_path = schemas[i].revision.file_path_yang;

        if (NULL != schema_path && 0 == strcmp(module_name, schemas[i].module_name)) {
            printf("Trying to install schema: %s\n", schema_path);
            if (NULL == lys_parse_path(ctx, schema_path, LYS_IN_YANG)) 
            {
                fprintf(stderr, "Failed to parse schema file '%s': %s (%s)",
                        schema_path, ly_errmsg(ctx), ly_errpath(ctx));
                return SR_ERR_OPERATION_FAILED;
                // continue;
            }
            break;
        }
    }

    data = lyd_parse_mem(ctx, notif_object, LYD_JSON, LYD_OPT_NOTIF);
    if (data == NULL)
    {
        printf("Could not create JSON object, not valid!\n");
        return SR_ERR_VALIDATION_FAILED;
    }

    LY_TREE_FOR(data->child, iter) {
        if (op_add_srval(&vnotif, &num_values, iter)) {
            printf("Could not transform libyang into sysrepo values...\n");
            return SR_ERR_OPERATION_FAILED;
        }
    }

    if (num_values == 0)
    {
        printf("Could not generate objects for sending inside the notif...\n");
        return SR_ERR_OPERATION_FAILED;
    }

    rc = sr_event_notif_send(sess, lyd_path(data), vnotif, num_values, SR_EV_NOTIF_DEFAULT);
    if (rc != SR_ERR_OK)
    {
        printf("Error: could not send notification...\n");
        return SR_ERR_OPERATION_FAILED;
    }

	return rc;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    const char *notif_object = NULL;
    const char *module_name = NULL;

    if (argc != 3) {
        printf("%s <module_name> <notification-object>\n", argv[0]);
        return EXIT_FAILURE;
    }
    module_name = argv[1];
    notif_object = argv[2];

    /* connect to sysrepo */
    rc = sr_connect("generic_notifications", SR_CONN_DEFAULT, &connection);
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

    rc = send_dummy_notif(session, module_name, notif_object);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by send_dummy_notif: %s\n", sr_strerror(rc));
        goto cleanup;
    }
 
    printf("Application exit reached, exiting.\n");

    return 0;

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




