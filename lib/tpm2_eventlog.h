/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TPM2_EVENTLOG_H
#define TPM2_EVENTLOG_H

#include <stdbool.h>
#include <stdlib.h>

#include <tss2/tss2_tpm2_types.h>

#include "efi_event.h"

typedef bool (*DIGEST2_CALLBACK)(TCG_DIGEST2 const *digest, size_t size,
                                 void *data);
typedef bool (*EVENT2_CALLBACK)(TCG_EVENT_HEADER2 const *event_hdr, size_t size,
                                void *data);
typedef bool (*EVENT2DATA_CALLBACK)(TCG_EVENT2 const *event, UINT32 type,
                                    void *data);
typedef bool (*SPECID_CALLBACK)(TCG_EVENT const *event, void *data);

bool digest2_accumulator_callback(TCG_DIGEST2 const *digest, size_t size,
                                  void *data);

bool parse_event2body(TCG_EVENT2 const *event, UINT32 type);
bool foreach_digest2(TCG_DIGEST2 const *event_hdr, size_t count, size_t size,
                     DIGEST2_CALLBACK callback, void *data);
bool parse_event2(TCG_EVENT_HEADER2 const *eventhdr, size_t buf_size,
                  size_t *event_size, size_t *digests_size);
bool foreach_event2(TCG_EVENT_HEADER2 const *eventhdr_start, size_t size,
                    EVENT2_CALLBACK event2hdr_cb,
                    DIGEST2_CALLBACK digest2_cb,
                    EVENT2DATA_CALLBACK event2_cb, void *data);
bool specid_event(TCG_EVENT const *event, size_t size, TCG_EVENT_HEADER2 **next);
bool parse_eventlog(BYTE const *eventlog, size_t size,
                    SPECID_CALLBACK specid_cb,
                    EVENT2_CALLBACK event2hdr_cb,
                    DIGEST2_CALLBACK digest2_cb,
                    EVENT2DATA_CALLBACK event2_cb, void *data);

#endif
