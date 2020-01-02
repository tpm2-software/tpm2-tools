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

bool digest2_accumulator_callback(TCG_DIGEST2 const *digest, size_t size,
                                  void *data);

bool foreach_digest2(TCG_DIGEST2 const *event_hdr, size_t count, size_t size,
                     DIGEST2_CALLBACK callback, void *data);
bool foreach_event2(TCG_EVENT_HEADER2 const *event_first, size_t size,
                    EVENT2_CALLBACK callback, void *data);

#endif
