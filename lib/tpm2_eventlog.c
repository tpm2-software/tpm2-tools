#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "efi_event.h"
#include "tpm2_alg_util.h"
#include "tpm2_eventlog.h"
#include "tpm2_openssl.h"

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
bool foreach_digest2(tpm2_eventlog_context *ctx, unsigned pcr_index, TCG_DIGEST2 const *digest, size_t count, size_t size) {

    if (digest == NULL) {
        LOG_ERR("digest cannot be NULL");
        return false;
    }

    /* Because pcr_index is used for array indexing and bit-shift operations it
       is 1 less than the max value */
    if (pcr_index > (TPM2_MAX_PCRS - 1)) {
        LOG_ERR("PCR Index %d is out of bounds for max available PCRS %d",
        pcr_index, TPM2_MAX_PCRS);
        return false;
    }

    bool ret = true;
    size_t i;
    for (i = 0; i < count; ++i) {
        if (size < sizeof(*digest)) {
            LOG_ERR("insufficient size for digest header");
            return false;
        }

        const TPMI_ALG_HASH alg = digest->AlgorithmId;
        const size_t alg_size = tpm2_alg_util_get_hash_size(alg);
        if (size < sizeof(*digest) + alg_size) {
            LOG_ERR("insufficient size for digest buffer");
            return false;
        }

        uint8_t *pcr = NULL;
        if (alg == TPM2_ALG_SHA1) {
            pcr = ctx->sha1_pcrs[pcr_index];
            ctx->sha1_used |= (1 << pcr_index);
        } else if (alg == TPM2_ALG_SHA256) {
            pcr = ctx->sha256_pcrs[pcr_index];
            ctx->sha256_used |= (1 << pcr_index);
        } else if (alg == TPM2_ALG_SHA384) {
            pcr = ctx->sha384_pcrs[pcr_index];
            ctx->sha384_used |= (1 << pcr_index);
        } else if (alg == TPM2_ALG_SHA512) {
            pcr = ctx->sha512_pcrs[pcr_index];
            ctx->sha512_used |= (1 << pcr_index);
        } else if (alg == TPM2_ALG_SM3_256) {
            pcr = ctx->sm3_256_pcrs[pcr_index];
            ctx->sm3_256_used |= (1 << pcr_index);
        } else {
            LOG_WARN("PCR%d algorithm %d unsupported", pcr_index, alg);
        }

        if (pcr && !tpm2_openssl_pcr_extend(alg, pcr, digest->Digest, alg_size)) {
            LOG_ERR("PCR%d extend failed", pcr_index);
            return false;
        }

        if (ctx->digest2_cb != NULL) {
            ret = ctx->digest2_cb(digest, alg_size, ctx->data);
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
    /* TCG PC Client FPF section 2.3.4.1 and 9.4.1 */
    case EV_POST_CODE:
        // the event is a string, so there are no length requirements.
        break;
    /* TCG PC Client FPF section 9.2.5 */
    case EV_S_CRTM_CONTENTS:
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        {
            UEFI_PLATFORM_FIRMWARE_BLOB *data =
                (UEFI_PLATFORM_FIRMWARE_BLOB*)event->Event;
            UNUSED(data);
            if (event->EventSize < sizeof(*data)) {
                LOG_ERR("size is insufficient for UEFI FW blob data");
                return false;
            }
        }
        break;
    case EV_EFI_BOOT_SERVICES_APPLICATION:
    case EV_EFI_BOOT_SERVICES_DRIVER:
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        {
            UEFI_IMAGE_LOAD_EVENT *data = (UEFI_IMAGE_LOAD_EVENT*)event->Event;
            UNUSED(data);
            if (event->EventSize < sizeof(*data)) {
                LOG_ERR("size is insufficient for UEFI image load event");
                return false;
            }
            /* what about the device path? */
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

    tpm2_eventlog_context ctx = {
        .data = digests_size,
        .digest2_cb = digest2_accumulator_callback,
    };
    ret = foreach_digest2(&ctx, eventhdr->PCRIndex,
                          eventhdr->Digests, eventhdr->DigestCount,
                          buf_size - sizeof(*eventhdr));
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

bool parse_sha1_log_event(tpm2_eventlog_context *ctx, TCG_EVENT const *event, size_t size,
                      size_t *event_size) {

    uint8_t *pcr = NULL;

    /* enough size for the 1.2 event structure */
    if (size < sizeof(*event)) {
        LOG_ERR("insufficient size for SpecID event header");
        return false;
    }
    *event_size = sizeof(*event);

    pcr = ctx->sha1_pcrs[ event->pcrIndex];
    if (pcr) {
        tpm2_openssl_pcr_extend(TPM2_ALG_SHA1, pcr, &event->digest[0], 20);
        ctx->sha1_used |= (1 << event->pcrIndex);
    }

    /* buffer size must be sufficient to hold event and event data */
    if (size < sizeof(*event) + (sizeof(event->event[0]) *
                                 event->eventDataSize)) {
        LOG_ERR("insufficient size for SpecID event data");
        return false;
    }
    *event_size += event->eventDataSize;
    return true;
}

bool foreach_sha1_log_event(tpm2_eventlog_context *ctx, TCG_EVENT const *eventhdr_start, size_t size) {

    if (eventhdr_start == NULL) {
        LOG_ERR("invalid parameter");
        return false;
    }

    if (size == 0) {
        return true;
    }

    TCG_EVENT const *eventhdr;
    size_t event_size;
    bool ret;

    for (eventhdr = eventhdr_start, event_size = 0;
         size > 0;
         eventhdr = (TCG_EVENT*)((uintptr_t)eventhdr + event_size),
         size -= event_size) {

        ret = parse_sha1_log_event(ctx, eventhdr, size, &event_size);
        if (!ret) {
            return ret;
        }

        TCG_EVENT2 *event = (TCG_EVENT2*)((uintptr_t)&eventhdr->eventDataSize);

        /* event header callback */
        if (ctx->log_eventhdr_cb != NULL) {
            ret = ctx->log_eventhdr_cb(eventhdr, event_size, ctx->data);
            if (ret != true) {
                return false;
            }
        }

        ret = parse_event2body(event, eventhdr->eventType);
        if (ret != true) {
            return ret;
        }

        /* event data callback */
        if (ctx->event2_cb != NULL) {
            ret = ctx->event2_cb(event, eventhdr->eventType, ctx->data,
                                 ctx->yaml_version);
            if (ret != true) {
                return false;
            }
        }
    }

    return true;
}

/*
 * For event types where digest can be verified from their event payload,
 * perform verification to ensure event payload was not tempered
 */
bool verify_digests(size_t eventnum, TCG_EVENT_HEADER2 const *eventhdr, TCG_EVENT2 *event) {

size_t i;

    TCG_DIGEST2 const *digest = eventhdr->Digests;
    UINT32 digest_count = eventhdr->DigestCount;
    UINT32 event_type = eventhdr->EventType;
    switch (event_type) {
    /* Digests of these event types are calculated directly from event->Event, thus can be verified  */
    case EV_S_CRTM_VERSION:
    case EV_SEPARATOR:
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EV_EFI_GPT_EVENT:
        for (i = 0; i < digest_count; i++) {
            TPMI_ALG_HASH alg = digest->AlgorithmId;
            TPM2B_DIGEST calc_digest;

            bool result = tpm2_openssl_hash_compute_data(alg, event->Event,
            event->EventSize, &calc_digest);
            if (!result) {
                LOG_WARN("Event %zu: Cannot calculate hash value from data", eventnum - 1);
                return false;
            }

            size_t alg_size = tpm2_alg_util_get_hash_size(alg);
            if (memcmp(calc_digest.buffer, digest->Digest, alg_size) != 0) {
                LOG_WARN("Event %zu's digest does not match its payload", eventnum - 1);
                return false;
            }

            digest = (TCG_DIGEST2*)((uintptr_t)digest->Digest + alg_size);
        }
        break;

    /* Shim and grub use this event type for various tasks */
    case EV_IPL:
        /* PCR9: used to measure loaded kernel and initramfs images which cannot
           be verified from eventlog alone */
        if (eventhdr->PCRIndex == 9) {
            return true;
        }

        /* PCR14: used to measure MokList, MokListX, and MokSBState which cannot
           be verified from eventlog alone */
        if (eventhdr->PCRIndex == 14) {
            return true;
        }

        /* PCR8: used to measure grub and kernel command line */
        if (eventhdr->PCRIndex != 8) {
            LOG_WARN("Event %zu is unexpectedly not extending either PCR 8, 9, or 14", eventnum - 1);
            return false;
        }

        /* Digest is applied on the string between "^[a-zA-Z_]+:? " and EOL,
         * including or excluding the trailing NULL character */
        for (i = 0; i < digest_count; i++) {
            size_t j;

            for (j = 0; j < event->EventSize; j++) {
                if (event->Event[j] == ' ')
                    break;
            }

            if (j + 1 >= event->EventSize || event->Event[event->EventSize - 1] != '\0') {
                LOG_WARN("Event %zu's event data is in unexpected format", eventnum - 1);
                return false;
            }

            TPM2B_DIGEST calc_digest;
            TPMI_ALG_HASH alg = digest->AlgorithmId;
            /* First try to calculate the hash excluding the trailing \0 */
            bool result = tpm2_openssl_hash_compute_data(alg,
            event->Event + (j + 1), event->EventSize - (j + 2), &calc_digest);
            if (!result) {
                LOG_WARN("Event %zu: Cannot calculate hash value from data", eventnum - 1);
                return false;
            }

            size_t alg_size = tpm2_alg_util_get_hash_size(alg);
            if (memcmp(calc_digest.buffer, digest->Digest, alg_size) != 0) {
                /* Next try to calculate the hash including the trailing \0 */
                bool result = tpm2_openssl_hash_compute_data(alg,
                event->Event + (j + 1), event->EventSize - (j + 1), &calc_digest);
                if (!result) {
                    LOG_WARN("Event %zu: Cannot calculate hash value from data", eventnum - 1);
                    return false;
                }

                if (memcmp(calc_digest.buffer, digest->Digest, alg_size) != 0) {
                    LOG_WARN("Event %zu's digest does not match its payload", eventnum - 1);
                    return false;
                }
            }
            digest = (TCG_DIGEST2*)((uintptr_t)digest->Digest + alg_size);
        }
        break;
    }

    return true;
}

bool foreach_event2(tpm2_eventlog_context *ctx, TCG_EVENT_HEADER2 const *eventhdr_start, size_t size) {

    if (eventhdr_start == NULL) {
        LOG_ERR("invalid parameter");
        return false;
    }
    if (size == 0) {
        return true;
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
        if (ctx->event2hdr_cb != NULL) {
            ret = ctx->event2hdr_cb(eventhdr, event_size, ctx->data);
            if (ret != true) {
                return false;
            }
        }

        /* digest callback foreach digest */
        ret = foreach_digest2(ctx, eventhdr->PCRIndex, eventhdr->Digests, eventhdr->DigestCount, digests_size);
        if (ret != true) {
            return false;
        }

        ret = parse_event2body(event, eventhdr->EventType);
        if (ret != true) {
            return ret;
        }

        /* digest verification */
        if (ctx->data != 0) {
            verify_digests(*(size_t*)ctx->data, eventhdr, event);
        }

        /* event data callback */
        if (ctx->event2_cb != NULL) {
            ret = ctx->event2_cb(event, eventhdr->EventType, ctx->data, ctx->yaml_version);
            if (ret != true) {
                return false;
            }
        }
    }

    return true;
}

bool specid_event(TCG_EVENT const *event, size_t size,
                  TCG_EVENT_HEADER2 **next) {

    /* enough size for the 1.2 event structure */
    if (size < sizeof(*event)) {
        LOG_ERR("insufficient size for SpecID event header");
        return false;
    }

    if (event->eventType != EV_NO_ACTION) {
        LOG_ERR("SpecID eventType must be EV_NO_ACTION");
        return false;
    }

    if (event->pcrIndex != 0) {
        LOG_ERR("bad pcrIndex for EV_NO_ACTION event");
        return false;
    }

    size_t i;
    for (i = 0; i < sizeof(event->digest); ++i) {
        if (event->digest[i] != 0) {
            LOG_ERR("SpecID digest data malformed");
            return false;
        }
    }

    /* eventDataSize must be sufficient to hold the specid event */
    if (event->eventDataSize < sizeof(TCG_SPECID_EVENT)) {
        LOG_ERR("invalid eventDataSize in specid event");
        return false;
    }

    /* buffer size must be sufficient to hold event and event data */
    if (size < sizeof(*event) + (sizeof(event->event[0]) *
                                 event->eventDataSize)) {
        LOG_ERR("insufficient size for SpecID event data");
        return false;
    }

    /* specid event must have 1 or more algorithms */
    TCG_SPECID_EVENT *event_specid = (TCG_SPECID_EVENT*)event->event;
    if (event_specid->numberOfAlgorithms == 0) {
        LOG_ERR("numberOfAlgorithms is invalid, may not be 0");
        return false;
    }

    /* buffer size must be sufficient to hold event, specid event & algs */
    if (size < sizeof(*event) + sizeof(*event_specid) +
               sizeof(event_specid->digestSizes[0]) *
               event_specid->numberOfAlgorithms) {
        LOG_ERR("insufficient size for SpecID algorithms");
        return false;
    }

    /* size must be sufficient for event, specid, algs & vendor stuff */
    if (size < sizeof(*event) + sizeof(*event_specid) +
               sizeof(event_specid->digestSizes[0]) *
               event_specid->numberOfAlgorithms + sizeof(TCG_VENDOR_INFO)) {
        LOG_ERR("insufficient size for VendorStuff");
        return false;
    }

    TCG_VENDOR_INFO *vendor = (TCG_VENDOR_INFO*)((uintptr_t)event_specid->digestSizes +
                                                 sizeof(*event_specid->digestSizes) *
                                                 event_specid->numberOfAlgorithms);
    /* size must be sufficient for vendorInfo */
    if (size < sizeof(*event) + sizeof(*event_specid) +
               sizeof(event_specid->digestSizes[0]) *
               event_specid->numberOfAlgorithms + sizeof(*vendor) +
               vendor->vendorInfoSize) {
        LOG_ERR("insufficient size for VendorStuff data");
        return false;
    }
    *next = (TCG_EVENT_HEADER2*)((uintptr_t)vendor->vendorInfo + vendor->vendorInfoSize);

    return true;
}

bool parse_eventlog(tpm2_eventlog_context *ctx, BYTE const *eventlog, size_t size) {

    if(!eventlog || (size < sizeof(TCG_EVENT))) {
        return false;
    }

    TCG_EVENT *event = (TCG_EVENT*)eventlog;
    if (event->eventType == EV_NO_ACTION) {
        TCG_EVENT_HEADER2 *next;
        bool ret = specid_event(event, size, &next);
        if (!ret) {
            return false;
        }

        size -= (uintptr_t)next - (uintptr_t)eventlog;

        if (ctx->specid_cb) {
            ret = ctx->specid_cb(event, ctx->data);
            if (!ret) {
                return false;
            }
        }

        return foreach_event2(ctx, next, size);
    }

    /* No specid event found. sha1 log format will be parsed. */
    return foreach_sha1_log_event(ctx, event, size);
}
