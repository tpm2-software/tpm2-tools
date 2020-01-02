/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_YAML_H
#define TPM2_EVENTLOG_YAML_H

#include <stdbool.h>
#include <stdlib.h>

#include "efi_event.h"
#include "tpm2_eventlog.h"

typedef struct {
    size_t digests_size;
    size_t digest_count;
} yaml_digest_cbdata_t;

char const *eventtype_to_string (UINT32 event_type);
bool yaml_eventheader2(TCG_EVENT_HEADER2 const *event_hdr, size_t size);
bool yaml_digest2(TCG_DIGEST2 const *digest, size_t size);
bool yaml_event2(TCG_EVENT2 const *event, size_t size);
bool yaml_digest2_callback(TCG_DIGEST2 const *digest, size_t size, void *data);
bool yaml_event2_callback(TCG_EVENT_HEADER2 const *event_hdr, size_t size,
                          void *data);

bool yaml_eventlog(UINT8 const *eventlog, size_t size);

#endif
