/*
 * wirebased-interface-status.h
 *
 *  Created on: Feb 15, 2019
 *      Author: parallels
 */

#ifndef EXAMPLES_NTSIMULATOR_WIREBASED_INTERFACE_STATUS_H_
#define EXAMPLES_NTSIMULATOR_WIREBASED_INTERFACE_STATUS_H_

#include "utils.h"

int wirebased_interface_status_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
        uint64_t request_id, const char *original_xpath, void *private_ctx);

#endif /* EXAMPLES_NTSIMULATOR_WIREBASED_INTERFACE_STATUS_H_ */
