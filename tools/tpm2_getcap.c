/*
 * Copyright (c) 2016-2018, Intel Corporation
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

#include <stdio.h>
#include <string.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

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

/* convenience macro to convert flags into "set" / "clear" strings */
#define prop_str(val) val ? "set" : "clear"
/* number of eleents in the capability_map array */
#define CAPABILITY_MAP_COUNT \
    (sizeof (capability_map) / sizeof (capability_map_entry_t))
/* Structure to map a string to the appropriate TPM2_CAP / TPM2_PT pair */
typedef struct capability_map_entry {
    char     *capability_string;
    TPM2_CAP   capability;
    UINT32    property;
    UINT32    count;
} capability_map_entry_t;
/*
 * Array of structurs for use as a lookup table to map string representation
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
    TPM2_CAP          capability;
    UINT32           property;
    UINT32           count;
} capability_opts_t;

static capability_opts_t options;

/*
 * This function uses the 'param' field in the capabilities_opts structure to
 * locate the same string in the capability_map array and then populates the
 * 'capability' and 'property' fields of the capability_opts_t structure with
 * the appropriate values from the capability_map.
 * Return values:
 * 0 - the function executed normally.
 * 1 - the parameter 'param' in the capability_opts_t structure is NULL.
 * 2 - no matching entry found in capability_map.
 */
int sanity_check_capability_opts (void) {

    if (options.capability_string == NULL) {
        LOG_ERR("missing capability string, see --help");
        return 2;
    }

    size_t i;
    for (i = 0; i < CAPABILITY_MAP_COUNT; ++i) {
        int cmp = strncmp(capability_map [i].capability_string,
                          options.capability_string,
                          strlen(capability_map [i].capability_string));
        if (cmp == 0) {
            options.capability = capability_map[i].capability;
            options.property   = capability_map[i].property;
            options.count      = capability_map[i].count;
            return 0;
        }
    }

    LOG_ERR("invalid capability string: %s, see --help",
            options.capability_string);

    return 2;
}

/*
 * There are a number of fixed TPM properties (tagged properties) that are
 * characters (8bit chars) packed into 32bit integers.
 */
void
get_uint32_as_chars (UINT32    value,
                     char     *buf)
{
    sprintf (buf, "%c%c%c%c",
             ((UINT8*)&value)[3],
             ((UINT8*)&value)[2],
             ((UINT8*)&value)[1],
             ((UINT8*)&value)[0]);
}
/*
 * Print string representations of the TPMA_MODES.
 */
void
tpm2_tool_output_tpma_modes (TPMA_MODES    modes)
{
    tpm2_tool_output ("TPM_PT_MODES: 0x%08x\n", modes);
    if (modes & TPMA_MODES_FIPS_140_2)
        tpm2_tool_output ("  TPMA_MODES_FIPS_140_2\n");
    if (modes& TPMA_MODES_RESERVED1_MASK)
        tpm2_tool_output ("  TPMA_MODES_RESERVED1 (these bits shouldn't be set)\n");
}
/*
 * Print string representation of the TPMA_PERMANENT attributes.
 */
void
dump_permanent_attrs (TPMA_PERMANENT attrs)
{
    tpm2_tool_output ("TPM_PT_PERSISTENT:\n");
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
void
dump_startup_clear_attrs (TPMA_STARTUP_CLEAR attrs)
{
    tpm2_tool_output ("TPM_PT_STARTUP_CLEAR:\n");
    tpm2_tool_output ("  phEnable:                  %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLE));
    tpm2_tool_output ("  shEnable:                  %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_SHENABLE));
    tpm2_tool_output ("  ehEnable:                  %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_EHENABLE));
    tpm2_tool_output ("  phEnableNV:                %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLENV));
    tpm2_tool_output ("  reserved1:                 %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_RESERVED1_MASK));
    tpm2_tool_output ("  orderly:                   %s\n", prop_str (attrs & TPMA_STARTUP_CLEAR_ORDERLY));
}
/*
 * Iterate over all fixed properties, call the unique print function for each.
 */
void
dump_tpm_properties_fixed (TPMS_TAGGED_PROPERTY properties[],
                           size_t               count)
{
    size_t i;
    char buf[5] = { 0, };

    for (i = 0; i < count; ++i) {
        TPM2_PT property = properties[i].property;
        UINT32 value    = properties[i].value;
        switch (property) {
        case TPM2_PT_FAMILY_INDICATOR:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_FAMILY_INDICATOR:\n"
                    "  as UINT32:                0x08%x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_LEVEL:
            tpm2_tool_output ("TPM_PT_LEVEL:               %d\n", value);
            break;
        case TPM2_PT_REVISION:
            tpm2_tool_output ("TPM_PT_REVISION:            %.2f\n", (float)value / 100);
            break;
        case TPM2_PT_DAY_OF_YEAR:
            tpm2_tool_output ("TPM_PT_DAY_OF_YEAR:         0x%08x\n", value);
            break;
        case TPM2_PT_YEAR:
            tpm2_tool_output ("TPM_PT_YEAR:                0x%08x\n", value);
            break;
        case TPM2_PT_MANUFACTURER:
            tpm2_tool_output ("TPM_PT_MANUFACTURER:        0x%08x\n", value);
            break;
        case TPM2_PT_VENDOR_STRING_1:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_1:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_STRING_2:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_2:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_STRING_3:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_3:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_STRING_4:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_4:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM2_PT_VENDOR_TPM_TYPE:
            tpm2_tool_output ("TPM_PT_VENDOR_TPM_TYPE:     0x%08x\n", value);
            break;
        case TPM2_PT_FIRMWARE_VERSION_1:
            tpm2_tool_output ("TPM_PT_FIRMWARE_VERSION_1:  0x%08x\n", value);
            break;
        case TPM2_PT_FIRMWARE_VERSION_2:
            tpm2_tool_output ("TPM_PT_FIRMWARE_VERSION_2:  0x%08x\n", value);
            break;
        case TPM2_PT_INPUT_BUFFER:
            tpm2_tool_output ("TPM_PT_INPUT_BUFFER:        0x%08x\n", value);
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
            tpm2_tool_output ("TPM_PT_HR_LOADED_MIN:       0x%08x\n", value);
            break;
        case TPM2_PT_ACTIVE_SESSIONS_MAX:
            tpm2_tool_output ("TPM_PT_ACTIVE_SESSIONS_MAX: 0x%08x\n", value);
            break;
        case TPM2_PT_PCR_COUNT:
            tpm2_tool_output ("TPM_PT_PCR_COUNT:           0x%08x\n", value);
            break;
        case TPM2_PT_PCR_SELECT_MIN:
            tpm2_tool_output ("TPM_PT_PCR_SELECT_MIN:      0x%08x\n", value);
            break;
        case TPM2_PT_CONTEXT_GAP_MAX:
            tpm2_tool_output ("TPM_PT_CONTEXT_GAP_MAX:     0x%08x\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_MAX:
            tpm2_tool_output ("TPM_PT_NV_COUNTERS_MAX:     0x%08x\n", value);
            break;
        case TPM2_PT_NV_INDEX_MAX:
            tpm2_tool_output ("TPM_PT_NV_INDEX_MAX:        0x%08x\n", value);
            break;
        case TPM2_PT_MEMORY:
            tpm2_tool_output ("TPM_PT_MEMORY:              0x%08x\n", value);
            break;
        case TPM2_PT_CLOCK_UPDATE:
            tpm2_tool_output ("TPM_PT_CLOCK_UPDATE:        0x%08x\n", value);
            break;
        case TPM2_PT_CONTEXT_HASH: /* this may be a TPM2_ALG_ID type */
            tpm2_tool_output ("TPM_PT_CONTEXT_HASH:        0x%08x\n", value);
            break;
        case TPM2_PT_CONTEXT_SYM: /* this is a TPM2_ALG_ID type */
            tpm2_tool_output ("TPM_PT_CONTEXT_SYM:         0x%08x\n", value);
            break;
        case TPM2_PT_CONTEXT_SYM_SIZE:
            tpm2_tool_output ("TPM_PT_CONTEXT_SYM_SIZE:    0x%08x\n", value);
            break;
        case TPM2_PT_ORDERLY_COUNT:
            tpm2_tool_output ("TPM_PT_ORDERLY_COUNT:       0x%08x\n", value);
            break;
        case TPM2_PT_MAX_COMMAND_SIZE:
            tpm2_tool_output ("TPM_PT_MAX_COMMAND_SIZE:    0x%08x\n", value);
            break;
        case TPM2_PT_MAX_RESPONSE_SIZE:
            tpm2_tool_output ("TPM_PT_MAX_RESPONSE_SIZE:   0x%08x\n", value);
            break;
        case TPM2_PT_MAX_DIGEST:
            tpm2_tool_output ("TPM_PT_MAX_DIGEST:          0x%08x\n", value);
            break;
        case TPM2_PT_MAX_OBJECT_CONTEXT:
            tpm2_tool_output ("TPM_PT_MAX_OBJECT_CONTEXT:  0x%08x\n", value);
            break;
        case TPM2_PT_MAX_SESSION_CONTEXT:
            tpm2_tool_output ("TPM_PT_MAX_SESSION_CONTEXT: 0x%08x\n", value);
            break;
        case TPM2_PT_PS_FAMILY_INDICATOR:
            tpm2_tool_output ("TPM_PT_PS_FAMILY_INDICATOR: 0x%08x\n", value);
            break;
        case TPM2_PT_PS_LEVEL:
            tpm2_tool_output ("TPM_PT_PS_LEVEL:            0x%08x\n", value);
            break;
        case TPM2_PT_PS_REVISION:
            tpm2_tool_output ("TPM_PT_PS_REVISION:         0x%08x\n", value);
            break;
        case TPM2_PT_PS_DAY_OF_YEAR:
            tpm2_tool_output ("TPM_PT_PS_DAY_OF_YEAR:      0x%08x\n", value);
            break;
        case TPM2_PT_PS_YEAR:
            tpm2_tool_output ("TPM_PT_PS_YEAR:             0x%08x\n", value);
            break;
        case TPM2_PT_SPLIT_MAX:
            tpm2_tool_output ("TPM_PT_SPLIT_MAX:           0x%08x\n", value);
            break;
        case TPM2_PT_TOTAL_COMMANDS:
            tpm2_tool_output ("TPM_PT_TOTAL_COMMANDS:      0x%08x\n", value);
            break;
        case TPM2_PT_LIBRARY_COMMANDS:
            tpm2_tool_output ("TPM_PT_LIBRARY_COMMANDS:    0x%08x\n", value);
            break;
        case TPM2_PT_VENDOR_COMMANDS:
            tpm2_tool_output ("TPM_PT_VENDOR_COMMANDS:     0x%08x\n", value);
            break;
        case TPM2_PT_NV_BUFFER_MAX:
            tpm2_tool_output ("TPM_PT_NV_BUFFER_MAX:       0x%08x\n", value);
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
void
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
        case TPM2_PT_HR_NV_INDEX:
            tpm2_tool_output("TPM2_PT_HR_NV_INDEX: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED:
            tpm2_tool_output ("TPM_PT_HR_LOADED:            0x%08x\n", value);
            break;
        case TPM2_PT_HR_LOADED_AVAIL:
            tpm2_tool_output ("TPM_PT_HR_LOADED_AVAIL:      0x%08x\n", value);
            break;
        case TPM2_PT_HR_ACTIVE:
            tpm2_tool_output ("TPM_PT_HR_ACTIVE:            0x%08x\n", value);
            break;
        case TPM2_PT_HR_ACTIVE_AVAIL:
            tpm2_tool_output ("TPM_PT_HR_ACTIVE_AVAIL:      0x%08x\n", value);
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
            tpm2_tool_output ("TPM_PT_NV_COUNTERS:          0x%08x\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_AVAIL:
            tpm2_tool_output ("TPM_PT_NV_COUNTERS_AVAIL:    0x%08x\n", value);
            break;
        case TPM2_PT_ALGORITHM_SET:
            tpm2_tool_output ("TPM_PT_ALGORITHM_SET:        0x%08x\n", value);
            break;
        case TPM2_PT_LOADED_CURVES:
            tpm2_tool_output ("TPM_PT_LOADED_CURVES:        0x%08x\n", value);
            break;
        case TPM2_PT_LOCKOUT_COUNTER:
            tpm2_tool_output ("TPM_PT_LOCKOUT_COUNTER:      0x%08x\n", value);
            break;
        case TPM2_PT_MAX_AUTH_FAIL:
            tpm2_tool_output ("TPM_PT_MAX_AUTH_FAIL:        0x%08x\n", value);
            break;
        case TPM2_PT_LOCKOUT_INTERVAL:
            tpm2_tool_output ("TPM_PT_LOCKOUT_INTERVAL:     0x%08x\n", value);
            break;
        case TPM2_PT_LOCKOUT_RECOVERY:
            tpm2_tool_output ("TPM_PT_LOCKOUT_RECOVERY:     0x%08x\n", value);
            break;
        case TPM2_PT_NV_WRITE_RECOVERY:
            tpm2_tool_output ("TPM_PT_NV_WRITE_RECOVERY:    0x%08x\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_0:
            tpm2_tool_output ("TPM_PT_AUDIT_COUNTER_0:      0x%08x\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_1:
            tpm2_tool_output ("TPM_PT_AUDIT_COUNTER_1:      0x%08x\n", value);
            break;
        default:
            LOG_ERR("Unknown property:   0x%08x\n", properties[i].property);
            break;
        }
    }
}
/*
 * Print data about TPM2_ALG_ID in human readable form.
 */
void
dump_algorithm_properties (TPM2_ALG_ID       id,
                           TPMA_ALGORITHM   alg_attrs)
{
    const char *id_name = tpm2_alg_util_algtostr(id);
    id_name = id_name ? id_name : "unknown";

    tpm2_tool_output ("TPMA_ALGORITHM for ALG_ID: 0x%x - %s\n", id, id_name);
    tpm2_tool_output ("  asymmetric: %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_ASYMMETRIC));
    tpm2_tool_output ("  symmetric:  %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_SYMMETRIC));
    tpm2_tool_output ("  hash:       %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_HASH));
    tpm2_tool_output ("  object:     %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_OBJECT));
    tpm2_tool_output ("  reserved:   0x%x\n", alg_attrs & TPMA_ALGORITHM_RESERVED1_MASK);
    tpm2_tool_output ("  signing:    %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_SIGNING));
    tpm2_tool_output ("  encrypting: %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_ENCRYPTING));
    tpm2_tool_output ("  method:     %s\n", prop_str (alg_attrs & TPMA_ALGORITHM_METHOD));
}

/*
 * Iterate over the count TPMS_ALG_PROPERTY entries and dump the
 * TPMA_ALGORITHM attributes for each.
 */
void
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
        { TPM2_CC_Commit, "commit" },
        { TPM2_CC_PolicyPassword, "policypassword" },
        { TPM2_CC_ZGen_2Phase, "zgen" },
        { TPM2_CC_EC_Ephemeral, "ec" },
        { TPM2_CC_PolicyNvWritten, "policynvwritten" }
    };

    if (cc < TPM2_CC_FIRST || cc > TPM2_CC_LAST) {
        return "Unknown";
    }

    size_t i;
    for(i=0; i < ARRAY_LEN(commands); i++) {
        if (cc == commands[i].cc) {
            return commands[i].name;
        }
    }

    /* Impossible condition*/
    return "Impossible";
}

/*
 * Pretty print the bit fields from the TPMA_CC (UINT32)
 */
void
dump_command_attrs (TPMA_CC tpma_cc)
{
    tpm2_tool_output ("TPMA_CC: 0x%08x\n", tpma_cc);
    tpm2_tool_output ("  name: %s\n", cc_to_str(tpma_cc & TPMA_CC_COMMANDINDEX_MASK));
    tpm2_tool_output ("  commandIndex: 0x%x\n", tpma_cc & TPMA_CC_COMMANDINDEX_MASK);
    tpm2_tool_output ("  reserved1:    0x%x\n", tpma_cc & TPMA_CC_RESERVED1_MASK);
    tpm2_tool_output ("  nv:           %s\n",   prop_str (tpma_cc & TPMA_CC_NV));
    tpm2_tool_output ("  extensive:    %s\n",   prop_str (tpma_cc & TPMA_CC_EXTENSIVE));
    tpm2_tool_output ("  flushed:      %s\n",   prop_str (tpma_cc & TPMA_CC_FLUSHED));
    tpm2_tool_output ("  cHandles:     0x%x\n", (tpma_cc & TPMA_CC_CHANDLES_MASK) >> TPMA_CC_CHANDLES_SHIFT);
    tpm2_tool_output ("  rHandle:      %s\n",   prop_str (tpma_cc & TPMA_CC_RHANDLE));
    tpm2_tool_output ("  V:            %s\n",   prop_str (tpma_cc & TPMA_CC_V));
    tpm2_tool_output ("  Res:          0x%x\n", (tpma_cc & TPMA_CC_RES_MASK) >> TPMA_CC_RES_SHIFT);
}
/*
 * Iterate over an array of TPM2_ECC_CURVEs and dump out a human readable
 * representation of each array member.
 */
void
dump_ecc_curves (TPM2_ECC_CURVE     curve[],
                 UINT32            count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        switch(curve[i]) {
            case TPM2_ECC_NIST_P192:
                tpm2_tool_output ("TPM2_ECC_NIST_P192 (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P224:
                tpm2_tool_output ("TPM2_ECC_NIST_P224 (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P256:
                tpm2_tool_output ("TPM2_ECC_NIST_P256 (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P384:
                tpm2_tool_output ("TPM2_ECC_NIST_P384 (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_NIST_P521:
                tpm2_tool_output ("TPM2_ECC_NIST_P521 (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_BN_P256:
                tpm2_tool_output ("TPM2_ECC_BN_P256   (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_BN_P638:
                tpm2_tool_output ("TPM2_ECC_BN_P638   (0x%04x)\n", curve[i]);
		break;
            case TPM2_ECC_SM2_P256:
                tpm2_tool_output ("TPM2_ECC_SM2_P256 (0x%04x)\n", curve[i]);
		break;
            default:
                tpm2_tool_output ("UNKNOWN          (0x%04x)\n", curve[i]);
		break;
        }
    }
}
/*
 * Iterate over an array of TPMA_CCs and dump out a human readable
 * representation of each array member.
 */
void
dump_command_attr_array (TPMA_CC     command_attributes[],
                         UINT32      count)
{
    size_t i;

    for (i = 0; i < count; ++i)
        dump_command_attrs (command_attributes [i]);
}
/*
 * Iterate over an array of TPML_HANDLEs and dump out the handle
 * values.
 */
void
dump_handles (TPM2_HANDLE     handles[],
              UINT32         count)
{
    UINT32 i;
    
    for (i = 0; i < count; ++i)
         tpm2_tool_output ("0x%08x\n", handles[i]);
}
/*
 * Query the TPM for TPM capabilities.
 */
TSS2_RC
get_tpm_capability_all (TSS2_SYS_CONTEXT *sapi_ctx,
                        TPMS_CAPABILITY_DATA  *capability_data) {
    TSS2_RC                rc;
    TPMI_YES_NO            more_data;

    rc = TSS2_RETRY_EXP(Tss2_Sys_GetCapability (sapi_ctx,
                                 NULL,
                                 options.capability,
                                 options.property,
                                 options.count,
                                 &more_data,
                                 capability_data,
                                 NULL));
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to GetCapability: capability: 0x%x, property: 0x%x, "
                 "TSS2_RC: 0x%x\n", options.capability, options.property, rc);
    } else if (more_data) {
        LOG_WARN("More data to be queried: capability: 0x%x, property: "
                 "0x%x\n", options.capability, options.property);
    }

    return rc;
}

/*
 * This function is a glorified switch statement. It uses the 'capability'
 * and 'property' fields from the capability_opts structure to find the right
 * print function for the capabilities in the 'capabilities' parameter.
 * On success it will return 0, if it failes (is unable to find an
 * appropriate print function for the provided 'capability' / 'property'
 * pair) then it will return 1.
 */
static int dump_tpm_capability (TPMU_CAPABILITIES *capabilities) {

    switch (options.capability) {
    case TPM2_CAP_ALGS:
        dump_algorithms (capabilities->algorithms.algProperties,
                         capabilities->algorithms.count);
        break;
    case TPM2_CAP_COMMANDS:
        dump_command_attr_array (capabilities->command.commandAttributes,
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
            return 1;
        }
        break;
    default:
        return 1;
    }
    return 0;
}

static bool on_option(char key, char *value) {

    UNUSED(key);

    options.capability_string = value;

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "capability", required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("c:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);
    TSS2_RC rc;
    TPMS_CAPABILITY_DATA capability_data = TPMS_CAPABILITY_DATA_EMPTY_INIT;
    int ret;

    ret = sanity_check_capability_opts();
    if (ret == 1) {
        LOG_ERR("Missing capability string. See --help.\n");
        return 1;
    } else if (ret == 2) {
        LOG_ERR("Invalid capability string. See --help.\n");
        return 1;
    }
    /* get requested capability from TPM, dump it to stdout */
    rc = get_tpm_capability_all(sapi_context, &capability_data);
    if (rc != TPM2_RC_SUCCESS)
        return 1;

    dump_tpm_capability(&capability_data.data);
    return 0;
}
