/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_YAML_H
#define TPM2_EVENTLOG_YAML_H

#include <stdbool.h>
#include <stdlib.h>

#include "efi_event.h"
#include "tpm2_eventlog.h"

char const *eventtype_to_string (UINT32 event_type);
void yaml_event2hdr(TCG_EVENT_HEADER2 const *event_hdr, size_t size);
bool yaml_digest2(TCG_DIGEST2 const *digest, size_t size);
char *yaml_uefi_var_unicodename(UEFI_VARIABLE_DATA *data);
bool yaml_event2data(TCG_EVENT2 const *event, UINT32 type, INT32 yaml_version);
bool yaml_digest2_callback(TCG_DIGEST2 const *digest, size_t size, void *data);
bool yaml_event2hdr_callback(TCG_EVENT_HEADER2 const *event_hdr, size_t size,
                             void *data);
bool yaml_event2data_callback(TCG_EVENT2 const *event, UINT32 type, void *data,
                              INT32 yaml_version);

bool yaml_eventlog(UINT8 const *eventlog, size_t size, INT32 yaml_version);

#endif
