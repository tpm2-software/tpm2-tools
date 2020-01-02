#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "efi_event.h"
#include "tpm2_alg_util.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_yaml.h"

char const *eventtype_to_string (UINT32 event_type) {

    switch (event_type) {
    case EV_PREBOOT_CERT:
        return "EV_PREBOOT_CERT";
    case EV_POST_CODE:
        return "EV_POST_CODE";
    case EV_UNUSED:
        return "EV_UNUSED";
    case EV_NO_ACTION:
        return "EV_NO_ACTION";
    case EV_SEPARATOR:
        return "EV_SEPARATOR";
    case EV_ACTION:
        return "EV_ACTION";
    case EV_EVENT_TAG:
        return "EV_EVENT_TAG";
    case EV_S_CRTM_CONTENTS:
        return "EV_S_CRTM_CONTENTS";
    case EV_S_CRTM_VERSION:
        return "EV_S_CRTM_VERSION";
    case EV_CPU_MICROCODE:
        return "EV_CPU_MICROCODE";
    case EV_PLATFORM_CONFIG_FLAGS:
        return "EV_PLATFORM_CONFIG_FLAGS";
    case EV_TABLE_OF_DEVICES:
        return "EV_TABLE_OF_DEVICES";
    case EV_COMPACT_HASH:
        return "EV_COMPACT_HASH";
    case EV_IPL:
        return "EV_IPL";
    case EV_IPL_PARTITION_DATA:
        return "EV_IPL_PARTITION_DATA";
    case EV_NONHOST_CODE:
        return "EV_NONHOST_CODE";
    case EV_NONHOST_CONFIG:
        return "EV_NONHOST_CONFIG";
    case EV_NONHOST_INFO:
        return "EV_NONHOST_INFO";
    case EV_OMIT_BOOT_DEVICE_EVENTS:
        return "EV_OMIT_BOOT_DEVICE_EVENTS";
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
        return "EV_EFI_VARIABLE_DRIVER_CONFIG";
    case EV_EFI_VARIABLE_BOOT:
        return "EV_EFI_VARIABLE_BOOT";
    case EV_EFI_BOOT_SERVICES_APPLICATION:
        return "EV_EFI_BOOT_SERVICES_APPLICATION";
    case EV_EFI_BOOT_SERVICES_DRIVER:
        return "EV_EFI_BOOT_SERVICES_DRIVER";
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        return "EV_EFI_RUNTIME_SERVICES_DRIVER";
    case EV_EFI_GPT_EVENT:
        return "EV_EFI_GPT_EVENT";
    case EV_EFI_ACTION:
        return "EV_EFI_ACTION";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
    case EV_EFI_HANDOFF_TABLES:
        return "EV_EFI_HANDOFF_TABLES";
    case EV_EFI_VARIABLE_AUTHORITY:
        return "EV_EFI_VARIABLE_AUTHORITY";
    default:
        return "Unknown event type";
    }
}
void bytes_to_str(uint8_t const *buf, size_t size, char *dest, size_t dest_size) {

    size_t i, j;

    for(i = 0, j = 0; i < size && j < dest_size - 1; ++i, j+=2) {
        sprintf(&dest[j], "%02x", buf[i]);
    }
    dest[j] = '\0';
}
bool yaml_eventheader2(TCG_EVENT_HEADER2 const *eventhdr, size_t size) {

    (void)size;

    printf("    PCRIndex: %d\n", eventhdr->PCRIndex);
    printf("    EventType: %s\n",
           eventtype_to_string(eventhdr->EventType));
    printf("    DigestCount: %d\n", eventhdr->DigestCount);
    return true;
}
/* converting byte buffer to hex string requires 2x, plus 1 for '\0' */
#define BYTES_TO_HEX_STRING_SIZE(byte_count) (byte_count * 2 + 1)
#define DIGEST_HEX_STRING_MAX BYTES_TO_HEX_STRING_SIZE(TPM2_MAX_DIGEST_BUFFER)
bool yaml_digest2(TCG_DIGEST2 const *digest, size_t size) {

    char hexstr[DIGEST_HEX_STRING_MAX] = { 0, };

    printf("        AlgorithmId: %s\n",
           tpm2_alg_util_algtostr(digest->AlgorithmId,
                                  tpm2_alg_util_flags_hash));
    bytes_to_str(digest->Digest, size, hexstr, sizeof(hexstr));
    printf("        Digest: %s\n", hexstr);

    return true;
}
#define EVENT_BUF_MAX BYTES_TO_HEX_STRING_SIZE(1024)
bool yaml_event2(TCG_EVENT2 const *event, size_t size) {

    if (size < sizeof(*event)) {
        LOG_ERR("size is insufficient for event");
        return false;
    }
    if (size < sizeof(*event) + event->EventSize) {
        LOG_ERR("size is insufficient for event body");
        return false;
    }
    printf("    EventSize: %" PRIu32 "\n", event->EventSize);

    if (event->EventSize > 0) {
        char hexstr[EVENT_BUF_MAX] = { 0, };

        bytes_to_str(event->Event, event->EventSize, hexstr, sizeof(hexstr));
        printf("    Event: %s\n", hexstr);
    }

    return true;
}
bool yaml_digest2_callback(TCG_DIGEST2 const *digest, size_t size,
                            void *data_in) {

    yaml_digest_cbdata_t *data = (yaml_digest_cbdata_t*)data_in;

    if (data == NULL) {
        LOG_ERR("callback requires user data");
        return false;
    }
    printf("      - Digest[%zu]:\n", data->digest_count++);
    data->digests_size += sizeof(*digest) + size;

    return yaml_digest2(digest, size);
}
bool yaml_event2_callback(TCG_EVENT_HEADER2 const *eventhdr, size_t size,
                           void *data_in) {

    TCG_EVENT2 *event;
    yaml_digest_cbdata_t cbdata = { 0, };
    bool ret;
    size_t *event_count = (size_t*)data_in;

    if (event_count == NULL) {
        LOG_ERR("callback requires user data");
        return false;
    }
    printf("- Event[%zu]:\n", (*event_count)++);

    yaml_eventheader2(eventhdr, size);

    printf("    Digests:\n");
    ret = foreach_digest2(eventhdr->Digests, eventhdr->DigestCount,
                          size - sizeof(*eventhdr), yaml_digest2_callback,
                          &cbdata);
    if (!ret) {
        return ret;
    }

    event = (TCG_EVENT2*)((uintptr_t)eventhdr->Digests +
                          cbdata.digests_size);
    yaml_event2(event, sizeof(*event) + event->EventSize);

    return true;
}
bool yaml_eventlog(UINT8 const *eventlog, size_t size) {

    size_t count = 0;

    printf("---\n");
    return foreach_event2((TCG_EVENT_HEADER2*)eventlog, size,
                          yaml_event2_callback, &count);
}
