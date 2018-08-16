/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_capability.h"

/* convenience macro to convert flags into "1" / "0" strings */
#define prop_str(val) val ? "1" : "0"
/* number of elements in the capability_map array */
#define CAPABILITY_MAP_COUNT \
    (sizeof (capability_map) / sizeof (capability_map_entry_t))
/* Structure to map a string to the appropriate TPM2_CAP / TPM2_PT pair */
typedef struct capability_map_entry {
    char     *capability_string;
    TPM2_CAP  capability;
    UINT32    property;
    UINT32    count;
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
};
/*
 * Structure to hold options for this tool.
 */
typedef struct capability_opts {
    char            *capability_string;
    TPM2_CAP         capability;
    UINT32           property;
    UINT32           count;
    bool             list;
} capability_opts_t;

static capability_opts_t options;

/*
 * This function uses the 'capability_string' field in the capabilities_opts
 * structure to locate the same string in the capability_map array and then
 * populates the 'capability' and 'property' fields of the capability_opts_t
 * structure with the appropriate values from the capability_map.
 * Return values:
 * 0 - the function executed normally.
 * 1 - no matching entry found in capability_map.
 */
int sanity_check_capability_opts (void) {

    if (options.capability_string == NULL) {
        LOG_ERR("missing capability string, see --help");
        return 2;
    }

    size_t i;
    for (i = 0; i < CAPABILITY_MAP_COUNT; ++i) {
        int cmp = strcmp(capability_map[i].capability_string,
                          options.capability_string);
        if (cmp == 0) {
            options.capability = capability_map[i].capability;
            options.property   = capability_map[i].property;
            options.count      = capability_map[i].count;
            return 0;
        }
    }

    LOG_ERR("invalid capability string: %s, see --help",
            options.capability_string);

    return 1;
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
get_uint32_as_chars (UINT32    value)
{
    static char buf[5];

    value = tpm2_util_ntoh_32(value);
    UINT8 *bytes = (UINT8 *)&value;

    /*
     * move the start of the string to the beginning
     * first non space character
     * Record the number of skips in i.
     */
    unsigned i;
    for(i=0; i < sizeof(value); i++) {
        UINT8 b = *bytes;
        if (!isspace(b)) {
            break;
        }
        bytes++;
    }

    /* record the number of trailing spaces in j */
    unsigned j;
    for(j=sizeof(value) - i; j > i; j--) {
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
static void
tpm2_tool_output_tpma_modes (TPMA_MODES    modes)
{
    tpm2_tool_output ("TPM2_PT_MODES:\n"
            "  raw: 0x%X\n", modes);
    if (modes & TPMA_MODES_FIPS_140_2)
        tpm2_tool_output ("  value: TPMA_MODES_FIPS_140_2\n");
    if (modes & TPMA_MODES_RESERVED1_MASK)
        tpm2_tool_output ("  value: TPMA_MODES_RESERVED1 (these bits shouldn't be set)\n");
}
/*
 * Print string representation of the TPMA_PERMANENT attributes.
 */
static void
dump_permanent_attrs (TPMA_PERMANENT attrs)
{
    tpm2_tool_output ("TPM2_PT_PERSISTENT:\n");
    tpm2_tool_output ("  ownerAuthSet:              %s\n", prop_str (attrs & TPMA_PERMANENT_OWNERAUTHSET));
    tpm2_tool_output ("  endorsementAuthSet:        %s\n", prop_str (attrs & TPMA_PERMANENT_ENDORSEMENTAUTHSET));
    tpm2_tool_output ("  lockoutAuthSet:            %s\n", prop_str (attrs & TPMA_PERMANENT_LOCKOUTAUTHSET));
    tpm2_tool_output ("  reserved1:                 %s\n", prop_str (attrs & TPMA_PERMANENT_RESERVED1_MASK));
    tpm2_tool_output ("  disableClear:              %s\n", prop_str (attrs & TPMA_PERMANENT_DISABLECLEAR));
    tpm2_tool_output ("  inLockout:                 %s\n", prop_str (attrs & TPMA_PERMANENT_INLOCKOUT));
    tpm2_tool_output ("  tpmGeneratedEPS:           %s\n", prop_str (attrs & TPMA_PERMANENT_TPMGENERATEDEPS));
    tpm2_tool_output ("  reserved2:                 %s\n", prop_str (attrs & TPMA_PERMANENT_RESERVED2_MASK));
}
/*
 * Print string representations of the TPMA_STARTUP_CLEAR attributes.
 */
static void
dump_startup_clear_attrs (TPMA_STARTUP_CLEAR attrs)
{
    tpm2_tool_output ("TPM2_PT_STARTUP_CLEAR:\n");
    tpm2_tool_output ("  phEnable:                  %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLE));
    tpm2_tool_output ("  shEnable:                  %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_SHENABLE));
    tpm2_tool_output ("  ehEnable:                  %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_EHENABLE));;
    tpm2_tool_output ("  phEnableNV:                %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLENV));
    tpm2_tool_output ("  reserved1:                 %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_RESERVED1_MASK));
    tpm2_tool_output ("  orderly:                   %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_ORDERLY));
}
/*
 * Iterate over all fixed properties, call the unique print function for each.
 */
static void
dump_tpm_properties_fixed (TPMS_TAGGED_PROPERTY properties[],
                           size_t               count)
{
    size_t i;
    char *buf;

    for (i = 0; i < count; ++i) {
        TPM2_PT property = properties[i].property;
        UINT32 value    = properties[i].value;
        switch (property) {
        case TPM2_PT_FAMILY_INDICATOR:
            buf = get_uint32_as_chars (value);
            tpm2_tool_output ("TPM2_PT_FAMILY_INDICATOR:\n"
                    "  raw: 0x08%x\n"
                    "  value: \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_LEVEL:
            tpm2_tool_output ("TPM2_PT_LEVEL:\n"
                    "  value: %d\n", value);
            break;
        case TPM2_PT_REVISION:
            tpm2_tool_output ("TPM2_PT_REVISION:\n"
                    "  value: %.2f\n", (float)value / 100);
            break;
        case TPM2_PT_DAY_OF_YEAR:
            tpm2_tool_output ("TPM2_PT_DAY_OF_YEAR:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_YEAR:
            tpm2_tool_output ("TPM2_PT_YEAR:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MANUFACTURER:
            tpm2_tool_output ("TPM2_PT_MANUFACTURER:\n"
                    " value        0x%X\n", value);
            break;
        case TPM2_PT_VENDOR_STRING_1:
            buf = get_uint32_as_chars (value);
            tpm2_tool_output ("TPM2_PT_VENDOR_STRING_1:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_STRING_2:
            buf = get_uint32_as_chars (value);
            tpm2_tool_output ("TPM2_PT_VENDOR_STRING_2:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_STRING_3:
            buf = get_uint32_as_chars (value);
            tpm2_tool_output ("TPM2_PT_VENDOR_STRING_3:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_STRING_4:
            buf = get_uint32_as_chars (value);
            tpm2_tool_output ("TPM2_PT_VENDOR_STRING_4:\n"
                    "  raw: 0x%X\n"
                    "  value: \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_TPM_TYPE:
            tpm2_tool_output ("TPM2_PT_VENDOR_TPM_TYPE:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_FIRMWARE_VERSION_1:
            tpm2_tool_output ("TPM2_PT_FIRMWARE_VERSION_1:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_FIRMWARE_VERSION_2:
            tpm2_tool_output ("TPM2_PT_FIRMWARE_VERSION_2:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_INPUT_BUFFER:
            tpm2_tool_output ("TPM2_PT_INPUT_BUFFER:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_TPM2_HR_TRANSIENT_MIN:
            tpm2_tool_output ("TPM2_PT_TPM2_HR_TRANSIENT_MIN:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_TPM2_HR_PERSISTENT_MIN:
            tpm2_tool_output ("TPM2_PT_TPM2_HR_PERSISTENT_MIN:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED_MIN:
            tpm2_tool_output ("TPM2_PT_HR_LOADED_MIN:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_ACTIVE_SESSIONS_MAX:
            tpm2_tool_output ("TPM2_PT_ACTIVE_SESSIONS_MAX:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PCR_COUNT:
            tpm2_tool_output ("TPM2_PT_PCR_COUNT:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PCR_SELECT_MIN:
            tpm2_tool_output ("TPM2_PT_PCR_SELECT_MIN:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_GAP_MAX:
            tpm2_tool_output ("TPM2_PT_CONTEXT_GAP_MAX:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_MAX:
            tpm2_tool_output ("TPM2_PT_NV_COUNTERS_MAX:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_NV_INDEX_MAX:
            tpm2_tool_output ("TPM2_PT_NV_INDEX_MAX:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MEMORY:
            tpm2_tool_output ("TPM2_PT_MEMORY:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_CLOCK_UPDATE:
            tpm2_tool_output ("TPM2_PT_CLOCK_UPDATE:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_HASH: /* this may be a TPM2_ALG_ID type */
            tpm2_tool_output ("TPM2_PT_CONTEXT_HASH:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_SYM: /* this is a TPM2_ALG_ID type */
            tpm2_tool_output ("TPM2_PT_CONTEXT_SYM:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_CONTEXT_SYM_SIZE:
            tpm2_tool_output ("TPM2_PT_CONTEXT_SYM_SIZE:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_ORDERLY_COUNT:
            tpm2_tool_output ("TPM2_PT_ORDERLY_COUNT:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_COMMAND_SIZE:
            tpm2_tool_output ("TPM2_PT_MAX_COMMAND_SIZE:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_RESPONSE_SIZE:
            tpm2_tool_output ("TPM2_PT_MAX_RESPONSE_SIZE:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_DIGEST:
            tpm2_tool_output ("TPM2_PT_MAX_DIGEST:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_OBJECT_CONTEXT:
            tpm2_tool_output ("TPM2_PT_MAX_OBJECT_CONTEXT:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_SESSION_CONTEXT:
            tpm2_tool_output ("TPM2_PT_MAX_SESSION_CONTEXT:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PS_FAMILY_INDICATOR:
            tpm2_tool_output ("TPM2_PT_PS_FAMILY_INDICATOR:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PS_LEVEL:
            tpm2_tool_output ("TPM2_PT_PS_LEVEL:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PS_REVISION:
            tpm2_tool_output ("TPM2_PT_PS_REVISION:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PS_DAY_OF_YEAR:
            tpm2_tool_output ("TPM2_PT_PS_DAY_OF_YEAR:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_PS_YEAR:
            tpm2_tool_output ("TPM2_PT_PS_YEAR:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_SPLIT_MAX:
            tpm2_tool_output ("TPM2_PT_SPLIT_MAX:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_TOTAL_COMMANDS:
            tpm2_tool_output ("TPM2_PT_TOTAL_COMMANDS:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_LIBRARY_COMMANDS:
            tpm2_tool_output ("TPM2_PT_LIBRARY_COMMANDS:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_VENDOR_COMMANDS:
            tpm2_tool_output ("TPM2_PT_VENDOR_COMMANDS:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_NV_BUFFER_MAX:
            tpm2_tool_output ("TPM2_PT_NV_BUFFER_MAX:\n"
                    "  value: 0x%X\n", value);
            break;
        case TPM2_PT_MODES:
            tpm2_tool_output_tpma_modes ((TPMA_MODES)value);
            break;
        }
    }
}
/*
 * Iterate over all variable properties, call the unique print function for each.
 */
static void
dump_tpm_properties_var (TPMS_TAGGED_PROPERTY properties[],
                         size_t               count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        TPM2_PT property = properties[i].property;
        UINT32 value    = properties[i].value;
        switch (property) {
        case TPM2_PT_PERMANENT:
            dump_permanent_attrs ((TPMA_PERMANENT)value);
            break;
        case TPM2_PT_STARTUP_CLEAR:
            dump_startup_clear_attrs ((TPMA_STARTUP_CLEAR)value);
            break;
        case TPM2_PT_TPM2_HR_NV_INDEX:
            tpm2_tool_output ("TPM2_PT_TPM2_HR_NV_INDEX: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED:
            tpm2_tool_output ("TPM2_PT_HR_LOADED: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED_AVAIL:
            tpm2_tool_output ("TPM2_PT_HR_LOADED_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_ACTIVE:
            tpm2_tool_output ("TPM2_PT_HR_ACTIVE: 0x%X\n", value);
            break;
        case TPM2_PT_HR_ACTIVE_AVAIL:
            tpm2_tool_output ("TPM2_PT_HR_ACTIVE_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_TPM2_HR_TRANSIENT_AVAIL:
            tpm2_tool_output ("TPM2_PT_TPM2_HR_TRANSIENT_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_TPM2_HR_PERSISTENT:
            tpm2_tool_output ("TPM2_PT_TPM2_HR_PERSISTENT: 0x%X\n", value);
            break;
        case TPM2_PT_TPM2_HR_PERSISTENT_AVAIL:
            tpm2_tool_output ("TPM2_PT_TPM2_HR_PERSISTENT_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS:
            tpm2_tool_output ("TPM2_PT_NV_COUNTERS: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_AVAIL:
            tpm2_tool_output ("TPM2_PT_NV_COUNTERS_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_ALGORITHM_SET:
            tpm2_tool_output ("TPM2_PT_ALGORITHM_SET: 0x%X\n", value);
            break;
        case TPM2_PT_LOADED_CURVES:
            tpm2_tool_output ("TPM2_PT_LOADED_CURVES: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_COUNTER:
            tpm2_tool_output ("TPM2_PT_LOCKOUT_COUNTER: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_AUTH_FAIL:
            tpm2_tool_output ("TPM2_PT_MAX_AUTH_FAIL: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_INTERVAL:
            tpm2_tool_output ("TPM2_PT_LOCKOUT_INTERVAL: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_RECOVERY:
            tpm2_tool_output ("TPM2_PT_LOCKOUT_RECOVERY: 0x%X\n", value);
            break;
        case TPM2_PT_NV_WRITE_RECOVERY:
            tpm2_tool_output ("TPM2_PT_NV_WRITE_RECOVERY: 0x%X\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_0:
            tpm2_tool_output ("TPM2_PT_AUDIT_COUNTER_0: 0x%X\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_1:
            tpm2_tool_output ("TPM2_PT_AUDIT_COUNTER_1: 0x%X\n", value);
            break;
        default:
            tpm2_tool_output ("unknown%X: 0x%X\n", value, value);
            break;
        }
    }
}
/*
 * Print data about TPM2_ALG_ID in human readable form.
 */
static void
dump_algorithm_properties (TPM2_ALG_ID       id,
                           TPMA_ALGORITHM   alg_attrs)
{
    const char *id_name = tpm2_alg_util_algtostr(id, tpm2_alg_util_flags_any);
    bool is_unknown = id_name == NULL;
    id_name = id_name ? id_name : "unknown";

    if (!is_unknown) {
        tpm2_tool_output ("%s:\n", id_name);
    } else {
        /* If it's unknown, we don't want N unknowns in the map, so
         * make them unknown42, unknown<alg id> since that's unique.
         * We do it this way, as most folks will want to just look up
         * if a given alg via "friendly" name like rsa is supported.
         */
        tpm2_tool_output ("%s%x:\n", id_name, id);
    }
    tpm2_tool_output ("  value:      0x%X\n", id);
    tpm2_tool_output ("  asymmetric: %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_ASYMMETRIC));
    tpm2_tool_output ("  symmetric:  %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_SYMMETRIC));
    tpm2_tool_output ("  hash:       %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_HASH));
    tpm2_tool_output ("  object:     %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_OBJECT));
    tpm2_tool_output ("  reserved:   0x%X\n", (alg_attrs & TPMA_ALGORITHM_RESERVED1_MASK) >> 4);
    tpm2_tool_output ("  signing:    %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_SIGNING));
    tpm2_tool_output ("  encrypting: %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_ENCRYPTING));
    tpm2_tool_output ("  method:     %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_METHOD));
}

/*
 * Iterate over the count TPMS_ALG_PROPERTY entries and dump the
 * TPMA_ALGORITHM attributes for each.
 */
static void
dump_algorithms (TPMS_ALG_PROPERTY   alg_properties[],
                 size_t              count)
{
    size_t i;

    for (i = 0; i < count; ++i)
        dump_algorithm_properties (alg_properties[i].alg,
                                   alg_properties[i].algProperties);
}

static const char *cc_to_str(UINT32 cc) {

    struct {
        UINT32 cc;
        const char *name;
    } commands[] = {
        { TPM2_CC_NV_UndefineSpaceSpecial, "nv" },
        { TPM2_CC_EvictControl, "evictcontrol" },
        { TPM2_CC_HierarchyControl, "hierarchycontrol" },
        { TPM2_CC_NV_UndefineSpace, "nv" },
        { TPM2_CC_ChangeEPS, "changeeps" },
        { TPM2_CC_ChangePPS, "changepps" },
        { TPM2_CC_Clear, "clear" },
        { TPM2_CC_ClearControl, "clearcontrol" },
        { TPM2_CC_ClockSet, "clockset" },
        { TPM2_CC_HierarchyChangeAuth, "hierarchychangeauth" },
        { TPM2_CC_NV_DefineSpace, "nv" },
        { TPM2_CC_PCR_Allocate, "pcr" },
        { TPM2_CC_PCR_SetAuthPolicy, "pcr" },
        { TPM2_CC_PP_Commands, "pp" },
        { TPM2_CC_SetPrimaryPolicy, "setprimarypolicy" },
        { TPM2_CC_FieldUpgradeStart, "fieldupgradestart" },
        { TPM2_CC_ClockRateAdjust, "clockrateadjust" },
        { TPM2_CC_CreatePrimary, "createprimary" },
        { TPM2_CC_NV_GlobalWriteLock, "nv" },
        { TPM2_CC_GetCommandAuditDigest, "getcommandauditdigest" },
        { TPM2_CC_NV_Increment, "nv" },
        { TPM2_CC_NV_SetBits, "nv" },
        { TPM2_CC_NV_Extend, "nv" },
        { TPM2_CC_NV_Write, "nv" },
        { TPM2_CC_NV_WriteLock, "nv" },
        { TPM2_CC_DictionaryAttackLockReset, "dictionaryattacklockreset" },
        { TPM2_CC_DictionaryAttackParameters, "dictionaryattackparameters" },
        { TPM2_CC_NV_ChangeAuth, "nv" },
        { TPM2_CC_PCR_Event, "pcr" },
        { TPM2_CC_PCR_Reset, "pcr" },
        { TPM2_CC_SequenceComplete, "sequencecomplete" },
        { TPM2_CC_SetAlgorithmSet, "setalgorithmset" },
        { TPM2_CC_SetCommandCodeAuditStatus, "setcommandcodeauditstatus" },
        { TPM2_CC_FieldUpgradeData, "fieldupgradedata" },
        { TPM2_CC_IncrementalSelfTest, "incrementalselftest" },
        { TPM2_CC_SelfTest, "selftest" },
        { TPM2_CC_Startup, "startup" },
        { TPM2_CC_Shutdown, "shutdown" },
        { TPM2_CC_StirRandom, "stirrandom" },
        { TPM2_CC_ActivateCredential, "activatecredential" },
        { TPM2_CC_Certify, "certify" },
        { TPM2_CC_PolicyNV, "policynv" },
        { TPM2_CC_CertifyCreation, "certifycreation" },
        { TPM2_CC_Duplicate, "duplicate" },
        { TPM2_CC_GetTime, "gettime" },
        { TPM2_CC_GetSessionAuditDigest, "getsessionauditdigest" },
        { TPM2_CC_NV_Read, "nv" },
        { TPM2_CC_NV_ReadLock, "nv" },
        { TPM2_CC_ObjectChangeAuth, "objectchangeauth" },
        { TPM2_CC_PolicySecret, "policysecret" },
        { TPM2_CC_Rewrap, "rewrap" },
        { TPM2_CC_Create, "create" },
        { TPM2_CC_ECDH_ZGen, "ecdh" },
        { TPM2_CC_HMAC, "hmac" },
        { TPM2_CC_Import, "import" },
        { TPM2_CC_Load, "load" },
        { TPM2_CC_Quote, "quote" },
        { TPM2_CC_RSA_Decrypt, "rsa" },
        { TPM2_CC_HMAC_Start, "hmac" },
        { TPM2_CC_SequenceUpdate, "sequenceupdate" },
        { TPM2_CC_Sign, "sign" },
        { TPM2_CC_Unseal, "unseal" },
        { TPM2_CC_PolicySigned, "policysigned" },
        { TPM2_CC_ContextLoad, "contextload" },
        { TPM2_CC_ContextSave, "contextsave" },
        { TPM2_CC_ECDH_KeyGen, "ecdh" },
        { TPM2_CC_EncryptDecrypt, "encryptdecrypt" },
        { TPM2_CC_FlushContext, "flushcontext" },
        { TPM2_CC_LoadExternal, "loadexternal" },
        { TPM2_CC_MakeCredential, "makecredential" },
        { TPM2_CC_NV_ReadPublic, "nv" },
        { TPM2_CC_PolicyAuthorize, "policyauthorize" },
        { TPM2_CC_PolicyAuthValue, "policyauthvalue" },
        { TPM2_CC_PolicyCommandCode, "policycommandcode" },
        { TPM2_CC_PolicyCounterTimer, "policycountertimer" },
        { TPM2_CC_PolicyCpHash, "policycphash" },
        { TPM2_CC_PolicyLocality, "policylocality" },
        { TPM2_CC_PolicyNameHash, "policynamehash" },
        { TPM2_CC_PolicyOR, "policyor" },
        { TPM2_CC_PolicyTicket, "policyticket" },
        { TPM2_CC_ReadPublic, "readpublic" },
        { TPM2_CC_RSA_Encrypt, "rsa" },
        { TPM2_CC_StartAuthSession, "startauthsession" },
        { TPM2_CC_VerifySignature, "verifysignature" },
        { TPM2_CC_ECC_Parameters, "ecc" },
        { TPM2_CC_FirmwareRead, "firmwareread" },
        { TPM2_CC_GetCapability, "getcapability" },
        { TPM2_CC_GetRandom, "getrandom" },
        { TPM2_CC_GetTestResult, "gettestresult" },
        { TPM2_CC_Hash, "hash" },
        { TPM2_CC_PCR_Read, "pcr" },
        { TPM2_CC_PolicyPCR, "policypcr" },
        { TPM2_CC_PolicyRestart, "policyrestart" },
        { TPM2_CC_ReadClock, "readclock" },
        { TPM2_CC_PCR_Extend, "pcr" },
        { TPM2_CC_PCR_SetAuthValue, "pcr" },
        { TPM2_CC_NV_Certify, "nv" },
        { TPM2_CC_EventSequenceComplete, "eventsequencecomplete" },
        { TPM2_CC_HashSequenceStart, "hashsequencestart" },
        { TPM2_CC_PolicyPhysicalPresence, "policyphysicalpresence" },
        { TPM2_CC_PolicyDuplicationSelect, "policyduplicationselect" },
        { TPM2_CC_PolicyGetDigest, "policygetdigest" },
        { TPM2_CC_TestParms, "testparms" },
        { TPM2_CC_Commit, "commit" },
        { TPM2_CC_PolicyPassword, "policypassword" },
        { TPM2_CC_ZGen_2Phase, "zgen" },
        { TPM2_CC_EC_Ephemeral, "ec" },
        { TPM2_CC_PolicyNvWritten, "policynvwritten" },
        { TPM2_CC_PolicyTemplate, "policytemplate" },
        { TPM2_CC_CreateLoaded, "createloaded" },
        { TPM2_CC_PolicyAuthorizeNV, "policyauthorizenv" },
        { TPM2_CC_EncryptDecrypt2, "encryptdecrypt2" },
        { TPM2_CC_AC_GetCapability, "getcapability" },
        { TPM2_CC_AC_Send, "acsend" },
        { TPM2_CC_Policy_AC_SendSelect, "policyacsendselect" },
    };

    if (cc < TPM2_CC_FIRST || cc > TPM2_CC_LAST) {
        static char buf[256];
        snprintf(buf, sizeof(buf), "unknown%X", cc);
        return buf;
    }

    size_t i;
    for(i=0; i < ARRAY_LEN(commands); i++) {
        if (cc == commands[i].cc) {
            return commands[i].name;
        }
    }

    /* Impossible condition*/
    return NULL;
}

/*
 * Pretty print the bit fields from the TPMA_CC (UINT32)
 */
static bool
dump_command_attrs (TPMA_CC tpma_cc)
{
    const char *value = cc_to_str(tpma_cc & TPMA_CC_COMMANDINDEX_MASK);
    if (!value) {
        return false;
    }
    tpm2_tool_output ("%s:\n", value);
    tpm2_tool_output ("  value: 0x%X\n", tpma_cc);
    tpm2_tool_output ("  commandIndex: 0x%x\n", tpma_cc & TPMA_CC_COMMANDINDEX_MASK);
    tpm2_tool_output ("  reserved1:    0x%x\n", (tpma_cc & TPMA_CC_RESERVED1_MASK) >> 16);
    tpm2_tool_output ("  nv:           %s\n",   prop_str (tpma_cc & TPMA_CC_NV));
    tpm2_tool_output ("  extensive:    %s\n",   prop_str (tpma_cc & TPMA_CC_EXTENSIVE));
    tpm2_tool_output ("  flushed:      %s\n",   prop_str (tpma_cc & TPMA_CC_FLUSHED));
    tpm2_tool_output ("  cHandles:     0x%x\n", tpma_cc & TPMA_CC_CHANDLES_MASK >> TPMA_CC_CHANDLES_SHIFT);
    tpm2_tool_output ("  rHandle:      %s\n",   prop_str (tpma_cc & TPMA_CC_RHANDLE));
    tpm2_tool_output ("  V:            %s\n",   prop_str (tpma_cc & TPMA_CC_V));
    tpm2_tool_output ("  Res:          0x%x\n", tpma_cc  & TPMA_CC_RES_MASK >> TPMA_CC_RES_SHIFT);
    return true;
}
/*
 * Iterate over an array of TPM2_ECC_CURVEs and dump out a human readable
 * representation of each array member.
 */
static void
dump_ecc_curves (TPM2_ECC_CURVE     curve[],
                 UINT32            count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        switch(curve[i]) {
            case TPM2_ECC_NIST_P192:
                tpm2_tool_output ("TPM2_ECC_NIST_P192: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P224:
                tpm2_tool_output ("TPM2_ECC_NIST_P224: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P256:
                tpm2_tool_output ("TPM2_ECC_NIST_P256: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P384:
                tpm2_tool_output ("TPM2_ECC_NIST_P384: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P521:
                tpm2_tool_output ("TPM2_ECC_NIST_P521: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_BN_P256:
                tpm2_tool_output ("TPM2_ECC_BN_P256: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_BN_P638:
                tpm2_tool_output ("TPM2_ECC_BN_P638: 0x%X\n", curve[i]);
		break;
            case TPM2_ECC_SM2_P256:
                tpm2_tool_output ("TPM2_ECC_SM2_P256: 0x%X\n", curve[i]);
		break;
            default:
                tpm2_tool_output ("unknown%X: 0x%X\n", curve[i], curve[i]);
		break;
        }
    }
}
/*
 * Iterate over an array of TPMA_CCs and dump out a human readable
 * representation of each array member.
 */
static bool
dump_command_attr_array (TPMA_CC     command_attributes[],
                         UINT32      count)
{
    size_t i;
    bool result = true;
    for (i = 0; i < count; ++i)
        result &= dump_command_attrs (command_attributes [i]);

    return result;
}
/*
 * Iterate over an array of TPML_HANDLEs and dump out the handle
 * values.
 */
static void
dump_handles (TPM2_HANDLE     handles[],
              UINT32         count)
{
    UINT32 i;
    
    for (i = 0; i < count; ++i)
         tpm2_tool_output ("- 0x%X\n", handles[i]);
}
/*
 * Query the TPM for TPM capabilities.
 */
static TSS2_RC
get_tpm_capability_all (ESYS_CONTEXT *context,
                        TPMS_CAPABILITY_DATA  **capability_data) {
    return tpm2_capability_get(context, options.capability, options.property,
                            options.count, capability_data);
}

/*
 * This function is a glorified switch statement. It uses the 'capability'
 * and 'property' fields from the capability_opts structure to find the right
 * print function for the capabilities in the 'capabilities' parameter.
 * On success it will return true, if it fails (is unable to find an
 * appropriate print function for the provided 'capability' / 'property'
 * pair or the print routine fails)  then it will return false.
 */
static bool dump_tpm_capability (TPMU_CAPABILITIES *capabilities) {

    bool result = true;
    switch (options.capability) {
    case TPM2_CAP_ALGS:
        dump_algorithms (capabilities->algorithms.algProperties,
                         capabilities->algorithms.count);
        break;
    case TPM2_CAP_COMMANDS:
        result = dump_command_attr_array (capabilities->command.commandAttributes,
                                 capabilities->command.count);
        break;
    case TPM2_CAP_TPM_PROPERTIES:
        switch (options.property) {
        case TPM2_PT_FIXED:
            dump_tpm_properties_fixed (capabilities->tpmProperties.tpmProperty,
                                       capabilities->tpmProperties.count);
            break;
        case TPM2_PT_VAR:
            dump_tpm_properties_var (capabilities->tpmProperties.tpmProperty,
                                     capabilities->tpmProperties.count);
            break;
        default:
            return 1;
        }
        break;
    case TPM2_CAP_ECC_CURVES:
	dump_ecc_curves (capabilities->eccCurves.eccCurves,
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
            dump_handles (capabilities->handles.handle,
                          capabilities->handles.count);
            break;
        default:
            return false;
        }
        break;
    default:
        return false;
    }
    return result;
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'c':
        options.capability_string = value;
        break;
    case 'l':
        options.list = true;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "capability", required_argument, NULL, 'c' },
        { "list",       no_argument,       NULL, 'l' },

    };

    *opts = tpm2_options_new("c:l", ARRAY_LEN(topts), topts, on_option, NULL,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (options.list && options.capability_string) {
        LOG_ERR("Cannot specify -l with -c.");
        return -1;
    }

    /* list known capabilities, ie -l option */
    if (options.list) {
        print_cap_map();
        return 0;
    }

    /* List a capability, ie -c <arg> option */
    TPMS_CAPABILITY_DATA *capability_data = NULL;
    int ret;

    ret = sanity_check_capability_opts();
    if (ret == 1) {
        LOG_ERR("Invalid capability string. See --help.\n");
        return -1;
    }
    /* get requested capability from TPM, dump it to stdout */
    if (!get_tpm_capability_all(context, &capability_data))
        return 1;

    bool result = dump_tpm_capability(&capability_data->data);
    free(capability_data);
    return !result;
}
