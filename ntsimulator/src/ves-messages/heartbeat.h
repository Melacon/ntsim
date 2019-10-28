/*
 * heartbeat.h
 *
 *  Created on: Oct 24, 2019
 *      Author: parallels
 */

#ifndef SRC_VES_MESSAGES_HEARTBEAT_H_
#define SRC_VES_MESSAGES_HEARTBEAT_H_

#include <curl/curl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <cjson/cJSON.h>

#define CURL_MEM_SIZE 2048

/**
 * cURL utilities
*/

struct MemoryStruct {
  char *memory;
  size_t size;
};

int _init_curl(void);
int cleanup_curl(void);

#endif /* SRC_VES_MESSAGES_HEARTBEAT_H_ */
