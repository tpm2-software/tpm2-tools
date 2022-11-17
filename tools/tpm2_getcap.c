/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_capability.h"
#include "tpm2_cc_util.h"
#include "tpm2_tool.h"

/*
 * Older versions of tpm2-tss misspelled these constants' names.
 * See https://github.com/tpm2-software/tpm2-tss/issues/1500.
 */
#ifndef TPM2_PT_HR_TRANSIENT_MIN
#define TPM2_PT_HR_TRANSIENT_MIN    ((TPM2_PT) (TPM2_PT_FIXED + 14))
#define TPM2_PT_HR_PERSISTENT_MIN   ((TPM2_PT) (TPM2_PT_FIXED + 15))
#define TPM2_PT_HR_NV_INDEX         ((TPM2_PT) (TPM2_PT_VAR + 2))
#define TPM2_PT_HR_TRANSIENT_AVAIL  ((TPM2_PT) (TPM2_PT_VAR + 7))
#define TPM2_PT_HR_PERSISTENT       ((TPM2_PT) (TPM2_PT_VAR + 8))
#define TPM2_PT_HR_PERSISTENT_AVAIL ((TPM2_PT) (TPM2_PT_VAR + 9))
#endif

/* convenience macro to convert flags into "1" / "0" strings */
#define prop_str(val) val ? "1" : "0"

/* number of elements in the capability_map array */
#define CAPABILITY_MAP_COUNT \
    (sizeof (capability_map) / sizeof (capability_map_entry_t))

/* Structure to map a string to the appropriate TPM2_CAP / TPM2_PT pair */
typedef struct capability_map_entry {
    char *capability_string;
    TPM2_CAP capability;
    UINT32 property;
    UINT32 count;
} capability_map_entry_t;
/*
 * Array of structures for use as a lookup table to map string representation
 * of a capability to the proper TPM2_CAP / TPM2_PT pair.
 */
capability_map_entry_t capability_map[] = {
    {
        .capability_string = "algorithms",
        .capability        = TPM2_CAP_ALGS,
        .property          = TPM2_ALG_FIRST,
        .count             = TPM2_MAX_CAP_ALGS,
    },
    {
        .capability_string = "commands",
        .capability        = TPM2_CAP_COMMANDS,
        .property          = TPM2_CC_FIRST,
        .count             = TPM2_MAX_CAP_CC,
    },
    {
        .capability_string = "pcrs",
        .capability        = TPM2_CAP_PCRS,
        .property          = 0,
        .count             = TPM2_MAX_TPM_PROPERTIES,
    },
    {
        .capability_string = "properties-fixed",
        .capability        = TPM2_CAP_TPM_PROPERTIES,
        .property          = TPM2_PT_FIXED,
        .count             = TPM2_MAX_TPM_PROPERTIES,
    },
    {
        .capability_string = "properties-variable",
        .capability        = TPM2_CAP_TPM_PROPERTIES,
        .property          = TPM2_PT_VAR,
        .count             = TPM2_MAX_TPM_PROPERTIES,
    },
    {
        .capability_string = "ecc-curves",
        .capability        = TPM2_CAP_ECC_CURVES,
        .property          = TPM2_ECC_NIST_P192,
        .count             = TPM2_MAX_ECC_CURVES,
    },
    {
        .capability_string = "handles-transient",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_TRANSIENT_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-persistent",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_PERSISTENT_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-permanent",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_PERMANENT_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-pcr",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_PCR_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-nv-index",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_NV_INDEX_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-loaded-session",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_LOADED_SESSION_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-saved-session",
        .capability        = TPM2_CAP_HANDLES,
        .property          = TPM2_ACTIVE_SESSION_FIRST,
        .count             = TPM2_MAX_CAP_HANDLES,
    },
#if defined(ESYS_4_0)
    {
        .capability_string = "vendor",
        .capability        = TPM2_CAP_VENDOR_PROPERTY,
        .property          = 1,
        .count             = TPM2_MAX_CAP_BUFFER,
    },
#endif
};
/*
 * Structure to hold options for this tool.
 */
typedef struct capability_opts {
    char *capability_string;
    TPM2_CAP capability;
    UINT32 property;
    UINT32 count;
    bool list;
    bool ignore_moredata;
} capability_opts_t;

static capability_opts_t options;

/*
 * This function uses the 'capability_string' field in the capabilities_opts
 * structure to locate the same string in the capability_map array and then
 * populates the 'capability' and 'property' fields of the capability_opts_t
 * structure with the appropriate values from the capability_map.
 * Return values:
 * true - the function executed normally.
 * false - no matching entry found in capability_map.
 */
bool sanity_check_capability_opts(void) {

    if (options.capability_string == NULL) {
        LOG_ERR("missing capability string, see --help");
        return false;
    }

    size_t i;

    for (i = 0; i < CAPABILITY_MAP_COUNT; ++i) {

        int cmp = strncmp(capability_map[i].capability_string,
                options.capability_string,
                strlen(capability_map[i].capability_string));
        if (cmp == 0) {

            UINT32 property = capability_map[i].property;

            char *colon = strchr(options.capability_string, ':');
            if (colon && capability_map[i].capability != TPM2_CAP_VENDOR_PROPERTY) {
                LOG_ERR("capability string: \"%s\" does not support a property suffix,"
                        "see --help",
                        options.capability_string);
                return false;
            } else if (colon && capability_map[i].capability == TPM2_CAP_VENDOR_PROPERTY) {
                char *value_str = &colon[1];
                if (value_str[0] != '\0') {
                    char *tail = NULL;
                    errno = 0;
                    property = strtoul(value_str, &tail, 0);
                    if (errno || tail == value_str) {
                        LOG_ERR("Could not convert vendor specific property, got: \"%s\"",
                                value_str);
                        return false;
                    }
                }
            }

            options.capability = capability_map[i].capability;
            options.property = property;
            options.count = capability_map[i].count;
            return true;
        }
    }

    LOG_ERR("invalid capability string: %s, see --help",
            options.capability_string);

    return false;
}

static void print_cap_map() {

    size_t i;
    for (i = 0; i < CAPABILITY_MAP_COUNT; ++i) {
        const char *capstr = capability_map[i].capability_string;
        tpm2_tool_output("- %s\n", capstr);
    }
}

/*
 * There are a number of fixed TPM properties (tagged properties) that are
 * characters (8bit chars) packed into 32bit integers, trim leading and trailing spaces
 */
static char *
get_uint32_as_chars(UINT32 value) {
    static char buf[5];

    value = tpm2_util_ntoh_32(value);
    UINT8 *bytes = (UINT8 *) &value;

    /*
     * move the start of the string to the beginning
     * first non space character
     * Record the number of skips in i.
     */
    unsigned i;
    for (i = 0; i < sizeof(value); i++) {
        UINT8 b = *bytes;
        if (!isspace(b)) {
            break;
        }
        bytes++;
    }

    /* record the number of trailing spaces in j */
    unsigned j;
    for (j = sizeof(value) - i; j > i; j--) {
        UINT8 b = bytes[j - 1];
        /* NULL bytes count as space */
        if (b && !isspace(b)) {
            break;
        }
    }

    memcpy(buf, bytes, j);
    buf[j] = '\0';
    return buf;
}
/*
 * Print string representations of the TPMA_MODES.
 */
static void tpm2_tool_output_tpma_modes(TPMA_MODES modes) {
    tpm2_tool_output("TPM2_PT_MODES:\n"
            "  raw: 0x%X\n", modes);
    if (modes & TPMA_MODES_FIPS_140_2)
        tpm2_tool_output("  value: TPMA_MODES_FIPS_140_2\n");
    if (modes & TPMA_MODES_RESERVED1_MASK)
        tpm2_tool_output(
                "  value: TPMA_MODES_RESERVED1 (these bits shouldn't be set)\n");
}
/*
 * Print string representation of the TPMA_PERMANENT attributes.
 */
static void dump_permanent_attrs(TPMA_PERMANENT attrs) {
    tpm2_tool_output("TPM2_PT_PERMANENT:\n");
    tpm2_tool_output("  ownerAuthSet:              %s\n",
            prop_str (attrs & TPMA_PERMANENT_OWNERAUTHSET));
    tpm2_tool_output("  endorsementAuthSet:        %s\n",
            prop_str (attrs & TPMA_PERMANENT_ENDORSEMENTAUTHSET));
    tpm2_tool_output("  lockoutAuthSet:            %s\n",
            prop_str (attrs & TPMA_PERMANENT_LOCKOUTAUTHSET));
    tpm2_tool_output("  reserved1:                 %s\n",
            prop_str (attrs & TPMA_PERMANENT_RESERVED1_MASK));
    tpm2_tool_output("  disableClear:              %s\n",
            prop_str (attrs & TPMA_PERMANENT_DISABLECLEAR));
    tpm2_tool_output("  inLockout:                 %s\n",
            prop_str (attrs & TPMA_PERMANENT_INLOCKOUT));
    tpm2_tool_output("  tpmGeneratedEPS:           %s\n",
            prop_str (attrs & TPMA_PERMANENT_TPMGENERATEDEPS));
    tpm2_tool_output("  reserved2:                 %s\n",
            prop_str (attrs & TPMA_PERMANENT_RESERVED2_MASK));
}
/*
 * Print string representations of the TPMA_STARTUP_CLEAR attributes.
 */
static void dump_startup_clear_attrs(TPMA_STARTUP_CLEAR attrs) {
    tpm2_tool_output("TPM2_PT_STARTUP_CLEAR:\n");
    tpm2_tool_output("  phEnable:                  %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLE));
    tpm2_tool_output("  shEnable:                  %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_SHENABLE));
    tpm2_tool_output("  ehEnable:                  %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_EHENABLE));;
    tpm2_tool_output("  phEnableNV:                %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLENV));
    tpm2_tool_output("  reserved1:                 %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_RESERVED1_MASK));
    tpm2_tool_output("  orderly:                   %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_ORDERLY));
}
/*
 * Iterate over all fixed properties, call the unique print function for each.
 */
static void dump_tpm_properties_fixed(TPMS_TAGGED_PROPERTY properties[],
        size_t count) {
    size_t i;
    char *buf;

    for (i = 0; i < count; ++i) {
        TPM2_PT property = properties[i].property;
        UINT32 value = properties[i].value;
        switch (property) {
        case TPM2_PT_FAMILY_INDICATOR:
            buf = get_uint32_as_chars(value);
            tpm2_tool_output("TPM2_PT_FAMILY_INDICATOR:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n", value, buf);
            break;
        case TPM2_PT_LEVEL:
            tpm2_tool_output("TPM2_PT_LEVEL:\n"
                    "  raw: %d\n", value);
            break;
        case TPM2_PT_REVISION:
            tpm2_tool_output("TPM2_PT_REVISION:\n"
                    "  raw: 0x%X\n"
                    "  value: %.2f\n", value, (float )value / 100);
            break;
        case TPM2_PT_DAY_OF_YEAR:
            tpm2_tool_output("TPM2_PT_DAY_OF_YEAR:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_YEAR:
            tpm2_tool_output("TPM2_PT_YEAR:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MANUFACTURER: {
            UINT32 he_value = tpm2_util_ntoh_32(value);
            tpm2_tool_output("TPM2_PT_MANUFACTURER:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%.*s\"\n", value, (int )sizeof(value),
                    (char * )&he_value);
        }
            break;
        case TPM2_PT_VENDOR_STRING_1:
            buf = get_uint32_as_chars(value);
            tpm2_tool_output("TPM2_PT_VENDOR_STRING_1:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n", value, buf);
            break;
        case TPM2_PT_VENDOR_STRING_2:
            buf = get_uint32_as_chars(value);
            tpm2_tool_output("TPM2_PT_VENDOR_STRING_2:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n", value, buf);
            break;
        case TPM2_PT_VENDOR_STRING_3:
            buf = get_uint32_as_chars(value);
            tpm2_tool_output("TPM2_PT_VENDOR_STRING_3:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n", value, buf);
            break;
        case TPM2_PT_VENDOR_STRING_4:
            buf = get_uint32_as_chars(value);
            tpm2_tool_output("TPM2_PT_VENDOR_STRING_4:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n", value, buf);
            break;
        case TPM2_PT_VENDOR_TPM_TYPE:
            tpm2_tool_output("TPM2_PT_VENDOR_TPM_TYPE:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_FIRMWARE_VERSION_1:
            tpm2_tool_output("TPM2_PT_FIRMWARE_VERSION_1:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_FIRMWARE_VERSION_2:
            tpm2_tool_output("TPM2_PT_FIRMWARE_VERSION_2:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_INPUT_BUFFER:
            tpm2_tool_output("TPM2_PT_INPUT_BUFFER:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_HR_TRANSIENT_MIN:
            tpm2_tool_output("TPM2_PT_HR_TRANSIENT_MIN:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_HR_PERSISTENT_MIN:
            tpm2_tool_output("TPM2_PT_HR_PERSISTENT_MIN:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED_MIN:
            tpm2_tool_output("TPM2_PT_HR_LOADED_MIN:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_ACTIVE_SESSIONS_MAX:
            tpm2_tool_output("TPM2_PT_ACTIVE_SESSIONS_MAX:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PCR_COUNT:
            tpm2_tool_output("TPM2_PT_PCR_COUNT:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PCR_SELECT_MIN:
            tpm2_tool_output("TPM2_PT_PCR_SELECT_MIN:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_GAP_MAX:
            tpm2_tool_output("TPM2_PT_CONTEXT_GAP_MAX:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_MAX:
            tpm2_tool_output("TPM2_PT_NV_COUNTERS_MAX:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_NV_INDEX_MAX:
            tpm2_tool_output("TPM2_PT_NV_INDEX_MAX:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MEMORY:
            tpm2_tool_output("TPM2_PT_MEMORY:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_CLOCK_UPDATE:
            tpm2_tool_output("TPM2_PT_CLOCK_UPDATE:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_HASH: /* this may be a TPM2_ALG_ID type */
            tpm2_tool_output("TPM2_PT_CONTEXT_HASH:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_SYM: /* this is a TPM2_ALG_ID type */
            tpm2_tool_output("TPM2_PT_CONTEXT_SYM:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_SYM_SIZE:
            tpm2_tool_output("TPM2_PT_CONTEXT_SYM_SIZE:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_ORDERLY_COUNT:
            tpm2_tool_output("TPM2_PT_ORDERLY_COUNT:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_COMMAND_SIZE:
            tpm2_tool_output("TPM2_PT_MAX_COMMAND_SIZE:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_RESPONSE_SIZE:
            tpm2_tool_output("TPM2_PT_MAX_RESPONSE_SIZE:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_DIGEST:
            tpm2_tool_output("TPM2_PT_MAX_DIGEST:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_OBJECT_CONTEXT:
            tpm2_tool_output("TPM2_PT_MAX_OBJECT_CONTEXT:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_SESSION_CONTEXT:
            tpm2_tool_output("TPM2_PT_MAX_SESSION_CONTEXT:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PS_FAMILY_INDICATOR:
            tpm2_tool_output("TPM2_PT_PS_FAMILY_INDICATOR:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PS_LEVEL:
            tpm2_tool_output("TPM2_PT_PS_LEVEL:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PS_REVISION:
            tpm2_tool_output("TPM2_PT_PS_REVISION:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PS_DAY_OF_YEAR:
            tpm2_tool_output("TPM2_PT_PS_DAY_OF_YEAR:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_PS_YEAR:
            tpm2_tool_output("TPM2_PT_PS_YEAR:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_SPLIT_MAX:
            tpm2_tool_output("TPM2_PT_SPLIT_MAX:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_TOTAL_COMMANDS:
            tpm2_tool_output("TPM2_PT_TOTAL_COMMANDS:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_LIBRARY_COMMANDS:
            tpm2_tool_output("TPM2_PT_LIBRARY_COMMANDS:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_VENDOR_COMMANDS:
            tpm2_tool_output("TPM2_PT_VENDOR_COMMANDS:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_NV_BUFFER_MAX:
            tpm2_tool_output("TPM2_PT_NV_BUFFER_MAX:\n"
                    "  raw: 0x%X\n", value);
            break;
        case TPM2_PT_MODES:
            tpm2_tool_output_tpma_modes((TPMA_MODES) value);
            break;
        }
    }
}
/*
 * Iterate over all variable properties, call the unique print function for each.
 */
static void dump_tpm_properties_var(TPMS_TAGGED_PROPERTY properties[],
        size_t count) {
    size_t i;

    for (i = 0; i < count; ++i) {
        TPM2_PT property = properties[i].property;
        UINT32 value = properties[i].value;
        switch (property) {
        case TPM2_PT_PERMANENT:
            dump_permanent_attrs((TPMA_PERMANENT) value);
            break;
        case TPM2_PT_STARTUP_CLEAR:
            dump_startup_clear_attrs((TPMA_STARTUP_CLEAR) value);
            break;
        case TPM2_PT_HR_NV_INDEX:
            tpm2_tool_output("TPM2_PT_HR_NV_INDEX: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED:
            tpm2_tool_output("TPM2_PT_HR_LOADED: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED_AVAIL:
            tpm2_tool_output("TPM2_PT_HR_LOADED_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_ACTIVE:
            tpm2_tool_output("TPM2_PT_HR_ACTIVE: 0x%X\n", value);
            break;
        case TPM2_PT_HR_ACTIVE_AVAIL:
            tpm2_tool_output("TPM2_PT_HR_ACTIVE_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_TRANSIENT_AVAIL:
            tpm2_tool_output("TPM2_PT_HR_TRANSIENT_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_PERSISTENT:
            tpm2_tool_output("TPM2_PT_HR_PERSISTENT: 0x%X\n", value);
            break;
        case TPM2_PT_HR_PERSISTENT_AVAIL:
            tpm2_tool_output("TPM2_PT_HR_PERSISTENT_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS:
            tpm2_tool_output("TPM2_PT_NV_COUNTERS: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_AVAIL:
            tpm2_tool_output("TPM2_PT_NV_COUNTERS_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_ALGORITHM_SET:
            tpm2_tool_output("TPM2_PT_ALGORITHM_SET: 0x%X\n", value);
            break;
        case TPM2_PT_LOADED_CURVES:
            tpm2_tool_output("TPM2_PT_LOADED_CURVES: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_COUNTER:
            tpm2_tool_output("TPM2_PT_LOCKOUT_COUNTER: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_AUTH_FAIL:
            tpm2_tool_output("TPM2_PT_MAX_AUTH_FAIL: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_INTERVAL:
            tpm2_tool_output("TPM2_PT_LOCKOUT_INTERVAL: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_RECOVERY:
            tpm2_tool_output("TPM2_PT_LOCKOUT_RECOVERY: 0x%X\n", value);
            break;
        case TPM2_PT_NV_WRITE_RECOVERY:
            tpm2_tool_output("TPM2_PT_NV_WRITE_RECOVERY: 0x%X\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_0:
            tpm2_tool_output("TPM2_PT_AUDIT_COUNTER_0: 0x%X\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_1:
            tpm2_tool_output("TPM2_PT_AUDIT_COUNTER_1: 0x%X\n", value);
            break;
        default:
            tpm2_tool_output("unknown%X: 0x%X\n", value, value);
            break;
        }
    }
}
/*
 * Print data about TPM2_ALG_ID in human readable form.
 */
static void dump_algorithm_properties(TPM2_ALG_ID id, TPMA_ALGORITHM alg_attrs) {
    const char *id_name = tpm2_alg_util_algtostr(id, tpm2_alg_util_flags_any);
    bool is_unknown = id_name == NULL;
    id_name = id_name ? id_name : "unknown";

    if (!is_unknown) {
        tpm2_tool_output("%s:\n", id_name);
    } else {
        /* If it's unknown, we don't want N unknowns in the map, so
         * make them unknown42, unknown<alg id> since that's unique.
         * We do it this way, as most folks will want to just look up
         * if a given alg via "friendly" name like rsa is supported.
         */
        tpm2_tool_output("%s%x:\n", id_name, id);
    }
    tpm2_tool_output("  value:      0x%X\n", id);
    tpm2_tool_output("  asymmetric: %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_ASYMMETRIC));
    tpm2_tool_output("  symmetric:  %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_SYMMETRIC));
    tpm2_tool_output("  hash:       %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_HASH));
    tpm2_tool_output("  object:     %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_OBJECT));
    tpm2_tool_output("  reserved:   0x%X\n",
            (alg_attrs & TPMA_ALGORITHM_RESERVED1_MASK) >> 4);
    tpm2_tool_output("  signing:    %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_SIGNING));
    tpm2_tool_output("  encrypting: %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_ENCRYPTING));
    tpm2_tool_output("  method:     %s\n",
            prop_str (alg_attrs & TPMA_ALGORITHM_METHOD));
}

/*
 * Iterate over the count TPMS_ALG_PROPERTY entries and dump the
 * TPMA_ALGORITHM attributes for each.
 */
static void dump_algorithms(TPMS_ALG_PROPERTY alg_properties[], size_t count) {
    size_t i;

    for (i = 0; i < count; ++i)
        dump_algorithm_properties(alg_properties[i].alg,
                alg_properties[i].algProperties);
}

/*
 * Pretty print the bit fields from the TPMA_CC (UINT32)
 */
static bool dump_command_attrs(TPMA_CC tpma_cc) {
    const char *value = tpm2_cc_util_to_str(
            tpma_cc & TPMA_CC_COMMANDINDEX_MASK);
    /* not found, make a hex version of it */
    if (!value) {
        /*
         * big enough for hex representation of
         * saturated U32 + 0x prefix and then some.
         */
        static char _buf[16];
        memset(_buf, 0, sizeof(_buf));
        int rc  = snprintf(_buf, sizeof(_buf), "0x%x", tpma_cc);
        /* ignore bytes, we don't care if it's truncated and it shouldnt happen */
        UNUSED(rc);
        value = _buf;
    }

    tpm2_tool_output("%s:\n", value);
    tpm2_tool_output("  value: 0x%X\n", tpma_cc);
    tpm2_tool_output("  commandIndex: 0x%x\n",
            tpma_cc & TPMA_CC_COMMANDINDEX_MASK);
    tpm2_tool_output("  reserved1:    0x%x\n",
            (tpma_cc & TPMA_CC_RESERVED1_MASK) >> 16);
    tpm2_tool_output("  nv:           %s\n", prop_str (tpma_cc & TPMA_CC_NV));
    tpm2_tool_output("  extensive:    %s\n",
            prop_str (tpma_cc & TPMA_CC_EXTENSIVE));
    tpm2_tool_output("  flushed:      %s\n",
            prop_str (tpma_cc & TPMA_CC_FLUSHED));
    tpm2_tool_output("  cHandles:     0x%x\n",
            (tpma_cc & TPMA_CC_CHANDLES_MASK) >> TPMA_CC_CHANDLES_SHIFT);
    tpm2_tool_output("  rHandle:      %s\n",
            prop_str (tpma_cc & TPMA_CC_RHANDLE));
    tpm2_tool_output("  V:            %s\n", prop_str (tpma_cc & TPMA_CC_V));
    tpm2_tool_output("  Res:          0x%x\n",
            (tpma_cc & TPMA_CC_RES_MASK) >> TPMA_CC_RES_SHIFT);
    return true;
}
/*
 * Iterate over an array of TPM2_ECC_CURVEs and dump out a human readable
 * representation of each array member.
 */
static void dump_ecc_curves(TPM2_ECC_CURVE curve[], UINT32 count) {
    size_t i;

    for (i = 0; i < count; ++i) {
        switch (curve[i]) {
        case TPM2_ECC_NIST_P192:
            tpm2_tool_output("TPM2_ECC_NIST_P192: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_NIST_P224:
            tpm2_tool_output("TPM2_ECC_NIST_P224: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_NIST_P256:
            tpm2_tool_output("TPM2_ECC_NIST_P256: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_NIST_P384:
            tpm2_tool_output("TPM2_ECC_NIST_P384: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_NIST_P521:
            tpm2_tool_output("TPM2_ECC_NIST_P521: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_BN_P256:
            tpm2_tool_output("TPM2_ECC_BN_P256: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_BN_P638:
            tpm2_tool_output("TPM2_ECC_BN_P638: 0x%X\n", curve[i]);
            break;
        case TPM2_ECC_SM2_P256:
            tpm2_tool_output("TPM2_ECC_SM2_P256: 0x%X\n", curve[i]);
            break;
        default:
            tpm2_tool_output("unknown%X: 0x%X\n", curve[i], curve[i]);
            break;
        }
    }
}
/*
 * Iterate over an array of TPMA_CCs and dump out a human readable
 * representation of each array member.
 */
static bool dump_command_attr_array(TPMA_CC command_attributes[], UINT32 count) {
    size_t i;
    bool result = true;
    for (i = 0; i < count; ++i)
        result &= dump_command_attrs(command_attributes[i]);

    return result;
}
/*
 * Iterate over an array of TPML_HANDLEs and dump out the handle
 * values.
 */
static void dump_handles(TPM2_HANDLE handles[], UINT32 count) {
    UINT32 i;

    for (i = 0; i < count; ++i)
        tpm2_tool_output("- 0x%X\n", handles[i]);
}
/*
 * Query the TPM for TPM capabilities.
 */
static tool_rc get_tpm_capability_all(ESYS_CONTEXT *context,
        TPMS_CAPABILITY_DATA **capability_data) {
    return tpm2_capability_get_ex(context, options.capability, options.property,
            options.count, options.ignore_moredata, capability_data);
}

/*
 * This function is a glorified switch statement. It uses the 'capability'
 * and 'property' fields from the capability_opts structure to find the right
 * print function for the capabilities in the 'capabilities' parameter.
 * On success it will return true, if it fails (is unable to find an
 * appropriate print function for the provided 'capability' / 'property'
 * pair or the print routine fails)  then it will return false.
 */
static bool dump_tpm_capability(TPMU_CAPABILITIES *capabilities) {

    bool result = true;
    switch (options.capability) {
    case TPM2_CAP_ALGS:
        dump_algorithms(capabilities->algorithms.algProperties,
                capabilities->algorithms.count);
        break;
    case TPM2_CAP_COMMANDS:
        result = dump_command_attr_array(
                capabilities->command.commandAttributes,
                capabilities->command.count);
        break;
    case TPM2_CAP_TPM_PROPERTIES:
        switch (options.property) {
        case TPM2_PT_FIXED:
            dump_tpm_properties_fixed(capabilities->tpmProperties.tpmProperty,
                    capabilities->tpmProperties.count);
            break;
        case TPM2_PT_VAR:
            dump_tpm_properties_var(capabilities->tpmProperties.tpmProperty,
                    capabilities->tpmProperties.count);
            break;
        default:
            return false;
        }
        break;
    case TPM2_CAP_ECC_CURVES:
        dump_ecc_curves(capabilities->eccCurves.eccCurves,
                capabilities->eccCurves.count);
        break;
    case TPM2_CAP_HANDLES:
        switch (options.property & TPM2_HR_RANGE_MASK) {
        case TPM2_HR_TRANSIENT:
        case TPM2_HR_PERSISTENT:
        case TPM2_HR_PERMANENT:
        case TPM2_HR_PCR:
        case TPM2_HR_NV_INDEX:
        case TPM2_HT_LOADED_SESSION << TPM2_HR_SHIFT:
        case TPM2_HT_SAVED_SESSION << TPM2_HR_SHIFT:
            dump_handles(capabilities->handles.handle,
                    capabilities->handles.count);
            break;
        default:
            return false;
        }
        break;
    case TPM2_CAP_PCRS:
        pcr_print_pcr_selections(&capabilities->assignedPCR);
        break;
#if defined(ESYS_4_0)
    case TPM2_CAP_VENDOR_PROPERTY: {

        TPM2B_MAX_CAP_BUFFER *buffer = &capabilities->vendor;
        tpm2_util_hexdump(buffer->buffer, buffer->size);
        tpm2_tool_output("\n");
    } break;
#endif
    default:
        LOG_ERR("Capability 0x%x not supported", options.capability);
        return false;
    }
    return result;
}

static bool on_option(char key, char *value) {

    UNUSED(value);

    switch (key) {
    case 'l':
        options.list = true;
        break;
    case 1:
        options.ignore_moredata = true;
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Only supports 1 capability group, got: %d", argc);
        return false;
    }

    options.capability_string = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "list",            no_argument, NULL, 'l' },
        { "ignore-moredata", no_argument, NULL,  1 },
    };

    *opts = tpm2_options_new("l", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (options.list && options.capability_string) {
        LOG_ERR("Cannot specify -l with a capability group.");
        return tool_rc_option_error;
    }

    /* list known capabilities, ie -l option */
    if (options.list) {
        print_cap_map();
        return tool_rc_success;
    }

    /* List a capability, ie <capability group> option */
    TPMS_CAPABILITY_DATA *capability_data = NULL;

    bool ret = sanity_check_capability_opts();
    if (!ret) {
        return tool_rc_option_error;
    }
    /* get requested capability from TPM, dump it to stdout */
    tool_rc rc = get_tpm_capability_all(context, &capability_data);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = dump_tpm_capability(&capability_data->data);
    free(capability_data);
    return result ? tool_rc_success : tool_rc_general_error;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("getcap", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
