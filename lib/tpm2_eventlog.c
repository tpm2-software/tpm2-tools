#include <inttypes.h>
#include <stdlib.h>
#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "efi_event.h"
#include "tpm2_alg_util.h"
#include "tpm2_eventlog.h"

bool digest2_accumulator_callback(TCG_DIGEST2 const *digest, size_t size,
                                  void *data){

    if (digest == NULL || data == NULL) {
        LOG_ERR("neither parameter may be NULL");
        return false;
    }
    size_t *accumulator = (size_t*)data;

    *accumulator += sizeof(*digest) + size;

    return true;
}
/*
 * Invoke callback function for each TCG_DIGEST2 structure in the provided
 * TCG_EVENT_HEADER2. The callback function is only invoked if this function
 * is first able to determine that the provided buffer is large enough to
 * hold the digest. The size of the digest is passed to the callback in the
 * 'size' parameter.
 */
bool foreach_digest2(TCG_DIGEST2 const *digest, size_t count, size_t size,
                     DIGEST2_CALLBACK callback, void *data) {

    if (digest == NULL) {
        LOG_ERR("digest cannot be NULL");
        return false;
    }

    bool ret = true;

    for (size_t i = 0; i < count; ++i) {
        if (size < sizeof(*digest)) {
            LOG_ERR("insufficient size for digest header");
            return false;
        }
        size_t alg_size = tpm2_alg_util_get_hash_size(digest->AlgorithmId);
        if (size < sizeof(*digest) + alg_size) {
            LOG_ERR("insufficient size for digest buffer");
            return false;
        }
        if (callback != NULL) {
            ret = callback(digest, alg_size, data);
            if (!ret) {
                LOG_ERR("callback failed for digest at %p with size %zu", digest, alg_size);
                break;
            }
        }
        size -= sizeof(*digest) + alg_size;
        digest = (TCG_DIGEST2*)((uintptr_t)digest->Digest + alg_size);
    }

    return ret;
}

/*
 * given the provided event type, parse event to ensure the structure / data
 * in the buffer doesn't exceed the buffer size
 */
bool parse_event2body(TCG_EVENT2 const *event, UINT32 type) {

    switch (type) {
    /* TCG PC Client FPF section 9.2.6 */
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EV_EFI_VARIABLE_BOOT:
    case EV_EFI_VARIABLE_AUTHORITY:
        {
            UEFI_VARIABLE_DATA *data = (UEFI_VARIABLE_DATA*)event->Event;
            if (event->EventSize < sizeof(*data)) {
                LOG_ERR("size is insufficient for UEFI variable data");
                return false;
            }

            if (event->EventSize < sizeof(*data) + data->UnicodeNameLength *
                sizeof(char16_t) + data->VariableDataLength)
            {
                LOG_ERR("size is insufficient for UEFI variable data");
                return false;
            }
        }
        break;
    /* TCG PC Client FPF section 9.2.5 */
    case EV_POST_CODE:
    case EV_S_CRTM_CONTENTS:
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        {
            UEFI_PLATFORM_FIRMWARE_BLOB *data =
                (UEFI_PLATFORM_FIRMWARE_BLOB*)event->Event;
            if (event->EventSize < sizeof(*data)) {
                LOG_ERR("size is insufficient for UEFI FW blob data");
                return false;
            }
        }
        break;
    }

    return true;
}
/*
 * parse event structure, including header, digests and event buffer ensuring
 * it all fits within the provided buffer (buf_size).
 */
bool parse_event2(TCG_EVENT_HEADER2 const *eventhdr, size_t buf_size,
                  size_t *event_size, size_t *digests_size) {

    bool ret;

    if (buf_size < sizeof(*eventhdr)) {
        LOG_ERR("corrupted log, insufficient size for event header: %zu", buf_size);
        return false;
    }
    *event_size = sizeof(*eventhdr);

    ret = foreach_digest2(eventhdr->Digests, eventhdr->DigestCount,
                          buf_size - sizeof(*eventhdr),
                          digest2_accumulator_callback, digests_size);
    if (ret != true) {
        return false;
    }
    *event_size += *digests_size;

    TCG_EVENT2 *event = (TCG_EVENT2*)((uintptr_t)eventhdr + *event_size);
    if (buf_size < *event_size + sizeof(*event)) {
        LOG_ERR("corrupted log: size insufficient for EventSize");
        return false;
    }
    *event_size += sizeof(*event);

    if (buf_size < *event_size + event->EventSize) {
        LOG_ERR("size insufficient for event data");
        return false;
    }
    *event_size += event->EventSize;

    return true;
}

bool foreach_event2(TCG_EVENT_HEADER2 const *eventhdr_start, size_t size,
                    EVENT2_CALLBACK event2hdr_cb,
                    DIGEST2_CALLBACK digest2_cb,
                    EVENT2DATA_CALLBACK event2_cb, void *data) {

    if (eventhdr_start == NULL || size == 0) {
        LOG_ERR("invalid parameter");
        return false;
    }

    TCG_EVENT_HEADER2 const *eventhdr;
    size_t event_size;
    bool ret;

    for (eventhdr = eventhdr_start, event_size = 0;
         size > 0;
         eventhdr = (TCG_EVENT_HEADER2*)((uintptr_t)eventhdr + event_size),
         size -= event_size) {

        size_t digests_size = 0;

        ret = parse_event2(eventhdr, size, &event_size, &digests_size);
        if (!ret) {
            return ret;
        }

        TCG_EVENT2 *event = (TCG_EVENT2*)((uintptr_t)eventhdr->Digests + digests_size);
        /* event header callback */
        if (event2hdr_cb != NULL) {
            ret = event2hdr_cb(eventhdr, event_size, data);
            if (ret != true) {
                return false;
            }
        }

        /* digest callback foreach digest */
        if (digest2_cb != NULL) {
            ret = foreach_digest2(eventhdr->Digests, eventhdr->DigestCount,
                                  digests_size, digest2_cb, data);
            if (ret != true) {
                return false;
            }
        }

        ret = parse_event2body(event, eventhdr->EventType);
        if (ret != true) {
            return ret;
        }

        /* event data callback */
        if (event2_cb != NULL) {
            ret = event2_cb(event, eventhdr->EventType, data);
            if (ret != true) {
                return false;
            }
        }
    }

    return true;
}
