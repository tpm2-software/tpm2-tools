/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_YAML_H
#define TPM2_EVENTLOG_YAML_H

#include <stdbool.h>
#include <stdlib.h>

#include "efi_event.h"
#include "tpm2_eventlog.h"

bool yaml_eventlog(UINT8 const *eventlog, size_t size);

#endif
