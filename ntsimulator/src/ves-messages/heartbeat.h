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
