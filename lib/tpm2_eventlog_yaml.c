#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include <tss2/tss2_tpm2_types.h>

#include "log.h"
#include "efi_event.h"
#include "tpm2_alg_util.h"
#include "tpm2_eventlog.h"
#include "tpm2_eventlog_yaml.h"
#include "tpm2_tool.h"
#include "tpm2_tool_output.h"

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

    for(i = 0, j = 0; i < size && j < dest_size - 2; ++i, j+=2) {
        sprintf(&dest[j], "%02x", buf[i]);
    }
    dest[j] = '\0';
}
void yaml_event2hdr(TCG_EVENT_HEADER2 const *eventhdr, size_t size) {

    (void)size;

    tpm2_tool_output("    PCRIndex: %d\n"
                     "    EventType: %s\n"
                     "    DigestCount: %d\n",
                     eventhdr->PCRIndex,
                     eventtype_to_string(eventhdr->EventType),
                     eventhdr->DigestCount);

    return;
}
void yaml_sha1_log_eventhdr(TCG_EVENT const *eventhdr, size_t size) {

    (void)size;

    tpm2_tool_output("    PCRIndex: %d\n"
                     "    EventType: %s\n",
                     eventhdr->pcrIndex,
                     eventtype_to_string(eventhdr->eventType));

    return;
}
/* converting byte buffer to hex string requires 2x, plus 1 for '\0' */
#define BYTES_TO_HEX_STRING_SIZE(byte_count) (byte_count * 2 + 1)
#define DIGEST_HEX_STRING_MAX BYTES_TO_HEX_STRING_SIZE(TPM2_MAX_DIGEST_BUFFER)
bool yaml_digest2(TCG_DIGEST2 const *digest, size_t size) {

    char hexstr[DIGEST_HEX_STRING_MAX] = { 0, };
    bytes_to_str(digest->Digest, size, hexstr, sizeof(hexstr));

    tpm2_tool_output("      - AlgorithmId: %s\n"
                     "        Digest: \"%s\"\n",
                     tpm2_alg_util_algtostr(digest->AlgorithmId, tpm2_alg_util_flags_hash),
                     hexstr);

    return true;
}
bool yaml_uefi_var_unicodename(UEFI_VARIABLE_DATA *data) {

    int ret = 0;
    char *mbstr = NULL, *tmp = NULL;
    mbstate_t st;

    memset(&st, '\0', sizeof(st));

    mbstr = tmp = calloc(data->UnicodeNameLength + 1, MB_CUR_MAX);
    if (mbstr == NULL) {
        LOG_ERR("failed to allocate data: %s\n", strerror(errno));
        return false;
    }

    for(size_t i = 0; i < data->UnicodeNameLength; ++i, tmp += ret) {
        ret = c16rtomb(tmp, data->UnicodeName[i], &st);
        if (ret < 0) {
            LOG_ERR("c16rtomb failed: %s", strerror(errno));
            free(mbstr);
            return false;
        }
    }
    tpm2_tool_output("      UnicodeName: %s\n", mbstr);
    free(mbstr);

    return true;
}
#define VAR_DATA_HEX_SIZE(data) BYTES_TO_HEX_STRING_SIZE(data->VariableDataLength)
static bool yaml_uefi_var_data(UEFI_VARIABLE_DATA *data) {

    if (data->VariableDataLength == 0) {
        return true;
    }

    char *var_data = calloc (1, VAR_DATA_HEX_SIZE(data));
    uint8_t *variable_data = (uint8_t*)&data->UnicodeName[
        data->UnicodeNameLength];
    if (var_data == NULL) {
        LOG_ERR("failled to allocate data: %s\n", strerror(errno));
        return false;
    }
    bytes_to_str(variable_data, data->VariableDataLength, var_data,
                 VAR_DATA_HEX_SIZE(data));

    tpm2_tool_output("      VariableData: \"%s\"\n", var_data);
    free(var_data);

    return true;
}
/*
 * TCG PC Client FPF section 2.3.4.1 and 9.4.1:
 * Usage of the event type EV_POST_CODE:
 * - If a combined event is measured, the event field SHOULD
 * be the string "POST CODE" in all caps. ...
 * - Embedded SMM code and the code that sets it up SHOULD use
 * the string "SMM CODE" in all caps...
 * - BIS code (excluding the BIS Certificate) should use event
 * field string of "BIS CODE" in all caps. ...
 * - ACPI flash data prior to any modifications ... should use
 * event field string of "ACPI DATA" in all caps.
 */
static bool yaml_uefi_post_code(const TCG_EVENT2 * const event)
{
    const char * const data = (const char *) event->Event;
    const size_t len = event->EventSize;

    tpm2_tool_output(
        "    Event: '%.*s'\n",
        (int) len,
        data);
    return true;
}
/*
 * TCG PC Client FPF section 9.2.6
 * The tpm2_eventlog module validates the event structure but nothing within
 * the event data buffer so we must do that here.
 */
static bool yaml_uefi_var(UEFI_VARIABLE_DATA *data) {

    bool ret;
    char uuidstr[37] = { 0 };

    uuid_unparse_lower(data->VariableName, uuidstr);

    tpm2_tool_output("    Event:\n"
                     "      VariableName: %s\n"
                     "      UnicodeNameLength: %"PRIu64"\n"
                     "      VariableDataLength: %" PRIu64 "\n",
                     uuidstr, data->UnicodeNameLength,
                     data->VariableDataLength);

    ret = yaml_uefi_var_unicodename(data);
    if (!ret) {
        return false;
    }

    return yaml_uefi_var_data(data);
}
/* TCG PC Client FPF section 9.2.5 */
bool yaml_uefi_platfwblob(UEFI_PLATFORM_FIRMWARE_BLOB *data) {

    tpm2_tool_output("    Event:\n"
                     "      BlobBase: 0x%" PRIx64 "\n"
                     "      BlobLength: 0x%" PRIx64 "\n",
                     data->BlobBase,
                     data->BlobLength);
    return true;
}
/* TCG PC Client PFP section 9.4.4 */
bool yaml_uefi_action(UINT8 const *action, size_t size) {

    tpm2_tool_output("    Event: '%.*s'\n", (int) size, action);

    return true;
}
/* TCG PC Client PFP section 9.2.3 */
bool yaml_uefi_image_load(UEFI_IMAGE_LOAD_EVENT *data, size_t size) {

    size_t devpath_len = (size - sizeof(*data)) * 2 + 1;
    char *buf = calloc (1, devpath_len);
    if (!buf) {
        LOG_ERR("failed to allocate memory: %s\n", strerror(errno));
        return false;
    }

    tpm2_tool_output("    Event:\n"
                     "      ImageLocationInMemory: 0x%" PRIx64 "\n"
                     "      ImageLengthInMemory: %" PRIu64 "\n"
                     "      ImageLinkTimeAddress: 0x%" PRIx64 "\n"
                     "      LengthOfDevicePath: %" PRIu64 "\n",
                     data->ImageLocationInMemory, data->ImageLengthInMemory,
                     data->ImageLinkTimeAddress, data->LengthOfDevicePath);

    bytes_to_str(data->DevicePath, size - sizeof(*data), buf, devpath_len);
    tpm2_tool_output("      DevicePath: \"%s\"\n", buf);

    free(buf);
    return true;
}
#define EVENT_BUF_MAX BYTES_TO_HEX_STRING_SIZE(1024)
bool yaml_event2data(TCG_EVENT2 const *event, UINT32 type) {

    char hexstr[EVENT_BUF_MAX] = { 0, };

    tpm2_tool_output("    EventSize: %" PRIu32 "\n", event->EventSize);

    if (event->EventSize == 0) {
        return true;
    }

    switch (type) {
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EV_EFI_VARIABLE_BOOT:
    case EV_EFI_VARIABLE_AUTHORITY:
        return yaml_uefi_var((UEFI_VARIABLE_DATA*)event->Event);
    case EV_POST_CODE:
        return yaml_uefi_post_code(event);
    case EV_S_CRTM_CONTENTS:
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
        return yaml_uefi_platfwblob((UEFI_PLATFORM_FIRMWARE_BLOB*)event->Event);
    case EV_EFI_ACTION:
        return yaml_uefi_action(event->Event, event->EventSize);
    case EV_EFI_BOOT_SERVICES_APPLICATION:
    case EV_EFI_BOOT_SERVICES_DRIVER:
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
        return yaml_uefi_image_load((UEFI_IMAGE_LOAD_EVENT*)event->Event,
                                    event->EventSize);
    default:
        bytes_to_str(event->Event, event->EventSize, hexstr, sizeof(hexstr));
        tpm2_tool_output("    Event: \"%s\"\n", hexstr);
        return true;
    }
}
bool yaml_event2data_callback(TCG_EVENT2 const *event, UINT32 type,
                              void *data) {

    (void)data;

    return yaml_event2data(event, type);
}
bool yaml_digest2_callback(TCG_DIGEST2 const *digest, size_t size,
                            void *data_in) {

    (void)data_in;
    return yaml_digest2(digest, size);
}

bool yaml_event2hdr_callback(TCG_EVENT_HEADER2 const *eventhdr, size_t size,
                             void *data_in) {

    size_t *count = (size_t*)data_in;

    if (count == NULL) {
        LOG_ERR("callback requires user data");
        return false;
    }

    tpm2_tool_output("  - EventNum: %zu\n", (*count)++);

    yaml_event2hdr(eventhdr, size);

    tpm2_tool_output("    Digests:\n");

    return true;
}
bool yaml_sha1_log_eventhdr_callback(TCG_EVENT const *eventhdr, size_t size,
                                     void *data_in) {

    (void)data_in;

    yaml_sha1_log_eventhdr(eventhdr, size);

    char hexstr[BYTES_TO_HEX_STRING_SIZE(sizeof(eventhdr->digest))] = { 0, };
    bytes_to_str(eventhdr->digest, sizeof(eventhdr->digest), hexstr, sizeof(hexstr));

    tpm2_tool_output("    DigestCount: 1\n"
                     "    Digests:\n"
                     "      - AlgorithmId: %s\n"
                     "        Digest: \"%s\"\n",
                     tpm2_alg_util_algtostr(TPM2_ALG_SHA1, tpm2_alg_util_flags_hash),
                     hexstr);
    return true;
}
void yaml_eventhdr(TCG_EVENT const *event, size_t *count) {

    /* digest is 20 bytes, 2 chars / byte and null terminator for string*/
    char digest_hex[2*sizeof(event->digest) + 1] = {};
    bytes_to_str(event->digest, sizeof(event->digest), digest_hex, sizeof(digest_hex));

    tpm2_tool_output("  - EventNum: %zu\n"
                     "    PCRIndex: %" PRIu32 "\n"
                     "    EventType: %s\n"
                     "    Digest: \"%s\"\n"
                     "    EventSize: %" PRIu32 "\n",
                     (*count)++, event->pcrIndex,
                     eventtype_to_string(event->eventType), digest_hex,
                     event->eventDataSize);
}

void yaml_specid(TCG_SPECID_EVENT* specid) {

    /* 'Signature' defined as byte buf, spec treats it like string w/o null. */
    char sig_str[sizeof(specid->Signature) + 1] = { '\0', };
    memcpy(sig_str, specid->Signature, sizeof(specid->Signature));

    tpm2_tool_output("    SpecID:\n"
                     "      - Signature: %s\n"
                     "        platformClass: %" PRIu32 "\n"
                     "        specVersionMinor: %" PRIu8 "\n"
                     "        specVersionMajor: %" PRIu8 "\n"
                     "        specErrata: %" PRIu8 "\n"
                     "        uintnSize: %" PRIu8 "\n"
                     "        numberOfAlgorithms: %" PRIu32 "\n"
                     "        Algorithms:\n",
                     sig_str,
                     specid->platformClass, specid->specVersionMinor,
                     specid->specVersionMajor, specid->specErrata,
                     specid->uintnSize,
                     specid->numberOfAlgorithms);

}
void yaml_specid_algs(TCG_SPECID_ALG const *alg, size_t count) {

    for (size_t i = 0; i < count; ++i, ++alg) {
        tpm2_tool_output("          - Algorithm[%zu]:\n"
                         "            algorithmId: %s\n"
                         "            digestSize: %" PRIu16 "\n",
                         i,
                         tpm2_alg_util_algtostr(alg->algorithmId,
                                                tpm2_alg_util_flags_hash),
                         alg->digestSize);
    }
}
bool yaml_specid_vendor(TCG_VENDOR_INFO *vendor) {

    char *vendinfo_str;

    tpm2_tool_output("        vendorInfoSize: %" PRIu8 "\n", vendor->vendorInfoSize);
    if (vendor->vendorInfoSize == 0) {
        return true;
    }
    vendinfo_str = calloc(1, vendor->vendorInfoSize * 2 + 1);
    if (vendinfo_str == NULL) {
        LOG_ERR("failed to allocate memory for vendorInfo: %s\n",
                strerror(errno));
        return false;
    }
    bytes_to_str(vendor->vendorInfo, vendor->vendorInfoSize, vendinfo_str,
                 vendor->vendorInfoSize * 2 + 1);
    tpm2_tool_output("        vendorInfo: \"%s\"\n", vendinfo_str);
    free(vendinfo_str);
    return true;
}
bool yaml_specid_event(TCG_EVENT const *event, size_t *count) {

    TCG_SPECID_EVENT *specid = (TCG_SPECID_EVENT*)event->event;
    TCG_SPECID_ALG *alg = (TCG_SPECID_ALG*)specid->digestSizes;
    TCG_VENDOR_INFO *vendor = (TCG_VENDOR_INFO*)(alg + specid->numberOfAlgorithms);

    yaml_eventhdr(event, count);
    yaml_specid(specid);
    yaml_specid_algs(alg, specid->numberOfAlgorithms);
    return yaml_specid_vendor(vendor);
}
bool yaml_specid_callback(TCG_EVENT const *event, void *data) {

    size_t *count = (size_t*)data;
    return yaml_specid_event(event, count);
}

static void yaml_eventlog_pcrs(tpm2_eventlog_context *ctx) {

    char hexstr[DIGEST_HEX_STRING_MAX] = { 0, };

    tpm2_tool_output("pcrs:\n");

    if (ctx->sha1_used != 0) {
        tpm2_tool_output("  sha1:\n");
        for(unsigned i = 0 ; i < TPM2_MAX_PCRS ; i++) {
            if ((ctx->sha1_used & (1 << i)) == 0)
                continue;
            bytes_to_str(ctx->sha1_pcrs[i], sizeof(ctx->sha1_pcrs[i]),
                hexstr, sizeof(hexstr));
            tpm2_tool_output("    %-2d : 0x%s\n", i, hexstr);
        }
    }

    if (ctx->sha256_used != 0) {
        tpm2_tool_output("  sha256:\n");
        for(unsigned i = 0 ; i < TPM2_MAX_PCRS ; i++) {
            if ((ctx->sha256_used & (1 << i)) == 0)
                continue;
            bytes_to_str(ctx->sha256_pcrs[i], sizeof(ctx->sha256_pcrs[i]),
                hexstr, sizeof(hexstr));
            tpm2_tool_output("    %-2d : 0x%s\n", i, hexstr);
        }
    }

    if (ctx->sha384_used != 0) {
        tpm2_tool_output("  sha384:\n");
        for(unsigned i = 0 ; i < TPM2_MAX_PCRS ; i++) {
            if ((ctx->sha384_used & (1 << i)) == 0)
                continue;
            bytes_to_str(ctx->sha384_pcrs[i], sizeof(ctx->sha384_pcrs[i]),
                hexstr, sizeof(hexstr));
            tpm2_tool_output("    %-2d : 0x%s\n", i, hexstr);
        }
    }

    if (ctx->sha512_used != 0) {
        tpm2_tool_output("  sha512:\n");
        for(unsigned i = 0 ; i < TPM2_MAX_PCRS ; i++) {
            if ((ctx->sha512_used & (1 << i)) == 0)
                continue;
            bytes_to_str(ctx->sha512_pcrs[i], sizeof(ctx->sha512_pcrs[i]),
                hexstr, sizeof(hexstr));
            tpm2_tool_output("    %-2d : 0x%s\n", i, hexstr);
        }
    }

    if (ctx->sm3_256_used != 0) {
        tpm2_tool_output("  sm3_256:\n");
        for(unsigned i = 0 ; i < TPM2_MAX_PCRS ; i++) {
            if ((ctx->sm3_256_used & (1 << i)) == 0)
                continue;
            bytes_to_str(ctx->sm3_256_pcrs[i], sizeof(ctx->sm3_256_pcrs[i]),
                hexstr, sizeof(hexstr));
            tpm2_tool_output("    %-2d : 0x%s\n", i, hexstr);
        }
    }
}

bool yaml_eventlog(UINT8 const *eventlog, size_t size) {

    size_t count = 0;
    tpm2_eventlog_context ctx = {
        .data = &count,
        .specid_cb = yaml_specid_callback,
        .event2hdr_cb = yaml_event2hdr_callback,
        .log_eventhdr_cb = yaml_sha1_log_eventhdr_callback,
        .digest2_cb = yaml_digest2_callback,
        .event2_cb = yaml_event2data_callback,
    };

    tpm2_tool_output("---\n");
    tpm2_tool_output("events:\n");
    bool rc = parse_eventlog(&ctx, eventlog, size);
    if (!rc) {
        return rc;
    }

    yaml_eventlog_pcrs(&ctx);
    return true;
}
