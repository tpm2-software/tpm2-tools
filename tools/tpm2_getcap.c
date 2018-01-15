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

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

/* convenience macro to convert flags into "set" / "clear" strings */
#define prop_str(val) val ? "set" : "clear"
/* number of eleents in the capability_map array */
#define CAPABILITY_MAP_COUNT \
    (sizeof (capability_map) / sizeof (capability_map_entry_t))
/* Structure to map a string to the appropriate TPM_CAP / TPM_PT pair */
typedef struct capability_map_entry {
    char     *capability_string;
    TPM_CAP   capability;
    UINT32    property;
    UINT32    count;
} capability_map_entry_t;
/*
 * Array of structurs for use as a lookup table to map string representation
 * of a capability to the proper TPM_CAP / TPM_PT pair.
 */
capability_map_entry_t capability_map[] = {
    {
        .capability_string = "algorithms",
        .capability        = TPM_CAP_ALGS,
        .property          = TPM_ALG_FIRST,
        .count             = MAX_CAP_ALGS,
    },
    {
        .capability_string = "commands",
        .capability        = TPM_CAP_COMMANDS,
        .property          = TPM_CC_FIRST,
        .count             = MAX_CAP_CC,
    },
    {
        .capability_string = "properties-fixed",
        .capability        = TPM_CAP_TPM_PROPERTIES,
        .property          = PT_FIXED,
        .count             = MAX_TPM_PROPERTIES,
    },
    {
        .capability_string = "properties-variable",
        .capability        = TPM_CAP_TPM_PROPERTIES,
        .property          = PT_VAR,
        .count             = MAX_TPM_PROPERTIES,
    },
    {
        .capability_string = "ecc-curves",
        .capability        = TPM_CAP_ECC_CURVES,
        .property          = TPM_ECC_NIST_P192,
        .count             = MAX_ECC_CURVES,
    },
    {
        .capability_string = "handles-transient",
        .capability        = TPM_CAP_HANDLES,
        .property          = TRANSIENT_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-persistent",
        .capability        = TPM_CAP_HANDLES,
        .property          = PERSISTENT_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-permanent",
        .capability        = TPM_CAP_HANDLES,
        .property          = PERMANENT_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-pcr",
        .capability        = TPM_CAP_HANDLES,
        .property          = PCR_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-nv-index",
        .capability        = TPM_CAP_HANDLES,
        .property          = NV_INDEX_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-loaded-session",
        .capability        = TPM_CAP_HANDLES,
        .property          = LOADED_SESSION_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
    {
        .capability_string = "handles-saved-session",
        .capability        = TPM_CAP_HANDLES,
        .property          = ACTIVE_SESSION_FIRST,
        .count             = MAX_CAP_HANDLES,
    },
};
/*
 * Structure to hold options for this tool.
 */
typedef struct capability_opts {
    char            *capability_string;
    TPM_CAP          capability;
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
    tpm2_tool_output ("TPM_PT_MODES: 0x%08x\n", modes.val);
    if (modes.FIPS_140_2)
        tpm2_tool_output ("  TPMA_MODES_FIPS_140_2\n");
    if (modes.reserved1)
        tpm2_tool_output ("  TPMA_MODES_RESERVED1 (these bits shouldn't be set)\n");
}
/*
 * Print string representation of the TPMA_PERMANENT attributes.
 */
void
dump_permanent_attrs (TPMA_PERMANENT attrs)
{
    tpm2_tool_output ("TPM_PT_PERSISTENT:\n");
    tpm2_tool_output ("  ownerAuthSet:              %s\n", prop_str (attrs.ownerAuthSet));
    tpm2_tool_output ("  endorsementAuthSet:        %s\n", prop_str (attrs.endorsementAuthSet));
    tpm2_tool_output ("  lockoutAuthSet:            %s\n", prop_str (attrs.lockoutAuthSet));
    tpm2_tool_output ("  reserved1:                 %s\n", prop_str (attrs.reserved1));
    tpm2_tool_output ("  disableClear:              %s\n", prop_str (attrs.disableClear));
    tpm2_tool_output ("  inLockout:                 %s\n", prop_str (attrs.inLockout));
    tpm2_tool_output ("  tpmGeneratedEPS:           %s\n", prop_str (attrs.tpmGeneratedEPS));
    tpm2_tool_output ("  reserved2:                 %s\n", prop_str (attrs.reserved2));
}
/*
 * Print string representations of the TPMA_STARTUP_CLEAR attributes.
 */
void
dump_startup_clear_attrs (TPMA_STARTUP_CLEAR attrs)
{
    tpm2_tool_output ("TPM_PT_STARTUP_CLEAR:\n");
    tpm2_tool_output ("  phEnable:                  %s\n", prop_str (attrs.phEnable));
    tpm2_tool_output ("  shEnable:                  %s\n", prop_str (attrs.shEnable));
    tpm2_tool_output ("  ehEnable:                  %s\n", prop_str (attrs.ehEnable));
    tpm2_tool_output ("  phEnableNV:                %s\n", prop_str (attrs.phEnableNV));
    tpm2_tool_output ("  reserved1:                 %s\n", prop_str (attrs.reserved1));
    tpm2_tool_output ("  orderly:                   %s\n", prop_str (attrs.orderly));
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
        TPM_PT property = properties[i].property;
        UINT32 value    = properties[i].value;
        switch (property) {
        case TPM_PT_FAMILY_INDICATOR:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_FAMILY_INDICATOR:\n"
                    "  as UINT32:                0x08%x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_LEVEL:
            tpm2_tool_output ("TPM_PT_LEVEL:               %d\n", value);
            break;
        case TPM_PT_REVISION:
            tpm2_tool_output ("TPM_PT_REVISION:            %.2f\n", (float)value / 100);
            break;
        case TPM_PT_DAY_OF_YEAR:
            tpm2_tool_output ("TPM_PT_DAY_OF_YEAR:         0x%08x\n", value);
            break;
        case TPM_PT_YEAR:
            tpm2_tool_output ("TPM_PT_YEAR:                0x%08x\n", value);
            break;
        case TPM_PT_MANUFACTURER:
            tpm2_tool_output ("TPM_PT_MANUFACTURER:        0x%08x\n", value);
            break;
        case TPM_PT_VENDOR_STRING_1:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_1:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_STRING_2:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_2:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_STRING_3:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_3:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_STRING_4:
            get_uint32_as_chars (value, buf);
            tpm2_tool_output ("TPM_PT_VENDOR_STRING_4:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_TPM_TYPE:
            tpm2_tool_output ("TPM_PT_VENDOR_TPM_TYPE:     0x%08x\n", value);
            break;
        case TPM_PT_FIRMWARE_VERSION_1:
            tpm2_tool_output ("TPM_PT_FIRMWARE_VERSION_1:  0x%08x\n", value);
            break;
        case TPM_PT_FIRMWARE_VERSION_2:
            tpm2_tool_output ("TPM_PT_FIRMWARE_VERSION_2:  0x%08x\n", value);
            break;
        case TPM_PT_INPUT_BUFFER:
            tpm2_tool_output ("TPM_PT_INPUT_BUFFER:        0x%08x\n", value);
            break;
        case TPM_PT_HR_TRANSIENT_MIN:
            tpm2_tool_output ("TPM_PT_HR_TRANSIENT_MIN:    0x%08x\n", value);
            break;
        case TPM_PT_HR_PERSISTENT_MIN:
            tpm2_tool_output ("TPM_PT_HR_PERSISTENT_MIN:   0x%08x\n", value);
            break;
        case TPM_PT_HR_LOADED_MIN:
            tpm2_tool_output ("TPM_PT_HR_LOADED_MIN:       0x%08x\n", value);
            break;
        case TPM_PT_ACTIVE_SESSIONS_MAX:
            tpm2_tool_output ("TPM_PT_ACTIVE_SESSIONS_MAX: 0x%08x\n", value);
            break;
        case TPM_PT_PCR_COUNT:
            tpm2_tool_output ("TPM_PT_PCR_COUNT:           0x%08x\n", value);
            break;
        case TPM_PT_PCR_SELECT_MIN:
            tpm2_tool_output ("TPM_PT_PCR_SELECT_MIN:      0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_GAP_MAX:
            tpm2_tool_output ("TPM_PT_CONTEXT_GAP_MAX:     0x%08x\n", value);
            break;
        case TPM_PT_NV_COUNTERS_MAX:
            tpm2_tool_output ("TPM_PT_NV_COUNTERS_MAX:     0x%08x\n", value);
            break;
        case TPM_PT_NV_INDEX_MAX:
            tpm2_tool_output ("TPM_PT_NV_INDEX_MAX:        0x%08x\n", value);
            break;
        case TPM_PT_MEMORY:
            tpm2_tool_output ("TPM_PT_MEMORY:              0x%08x\n", value);
            break;
        case TPM_PT_CLOCK_UPDATE:
            tpm2_tool_output ("TPM_PT_CLOCK_UPDATE:        0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_HASH: /* this may be a TPM_ALG_ID type */
            tpm2_tool_output ("TPM_PT_CONTEXT_HASH:        0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_SYM: /* this is a TPM_ALG_ID type */
            tpm2_tool_output ("TPM_PT_CONTEXT_SYM:         0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_SYM_SIZE:
            tpm2_tool_output ("TPM_PT_CONTEXT_SYM_SIZE:    0x%08x\n", value);
            break;
        case TPM_PT_ORDERLY_COUNT:
            tpm2_tool_output ("TPM_PT_ORDERLY_COUNT:       0x%08x\n", value);
            break;
        case TPM_PT_MAX_COMMAND_SIZE:
            tpm2_tool_output ("TPM_PT_MAX_COMMAND_SIZE:    0x%08x\n", value);
            break;
        case TPM_PT_MAX_RESPONSE_SIZE:
            tpm2_tool_output ("TPM_PT_MAX_RESPONSE_SIZE:   0x%08x\n", value);
            break;
        case TPM_PT_MAX_DIGEST:
            tpm2_tool_output ("TPM_PT_MAX_DIGEST:          0x%08x\n", value);
            break;
        case TPM_PT_MAX_OBJECT_CONTEXT:
            tpm2_tool_output ("TPM_PT_MAX_OBJECT_CONTEXT:  0x%08x\n", value);
            break;
        case TPM_PT_MAX_SESSION_CONTEXT:
            tpm2_tool_output ("TPM_PT_MAX_SESSION_CONTEXT: 0x%08x\n", value);
            break;
        case TPM_PT_PS_FAMILY_INDICATOR:
            tpm2_tool_output ("TPM_PT_PS_FAMILY_INDICATOR: 0x%08x\n", value);
            break;
        case TPM_PT_PS_LEVEL:
            tpm2_tool_output ("TPM_PT_PS_LEVEL:            0x%08x\n", value);
            break;
        case TPM_PT_PS_REVISION:
            tpm2_tool_output ("TPM_PT_PS_REVISION:         0x%08x\n", value);
            break;
        case TPM_PT_PS_DAY_OF_YEAR:
            tpm2_tool_output ("TPM_PT_PS_DAY_OF_YEAR:      0x%08x\n", value);
            break;
        case TPM_PT_PS_YEAR:
            tpm2_tool_output ("TPM_PT_PS_YEAR:             0x%08x\n", value);
            break;
        case TPM_PT_SPLIT_MAX:
            tpm2_tool_output ("TPM_PT_SPLIT_MAX:           0x%08x\n", value);
            break;
        case TPM_PT_TOTAL_COMMANDS:
            tpm2_tool_output ("TPM_PT_TOTAL_COMMANDS:      0x%08x\n", value);
            break;
        case TPM_PT_LIBRARY_COMMANDS:
            tpm2_tool_output ("TPM_PT_LIBRARY_COMMANDS:    0x%08x\n", value);
            break;
        case TPM_PT_VENDOR_COMMANDS:
            tpm2_tool_output ("TPM_PT_VENDOR_COMMANDS:     0x%08x\n", value);
            break;
        case TPM_PT_NV_BUFFER_MAX:
            tpm2_tool_output ("TPM_PT_NV_BUFFER_MAX:       0x%08x\n", value);
            break;
        case TPM_PT_MODES:
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
        TPM_PT property = properties[i].property;
        UINT32 value    = properties[i].value;
        switch (property) {
        case TPM_PT_PERMANENT:
            dump_permanent_attrs ((TPMA_PERMANENT)value);
            break;
        case TPM_PT_STARTUP_CLEAR:
            dump_startup_clear_attrs ((TPMA_STARTUP_CLEAR)value);
            break;
        case TPM_PT_HR_NV_INDEX:
            tpm2_tool_output ("TPM_PT_HR_NV_INDEX:          0x%08x\n", value);
            break;
        case TPM_PT_HR_LOADED:
            tpm2_tool_output ("TPM_PT_HR_LOADED:            0x%08x\n", value);
            break;
        case TPM_PT_HR_LOADED_AVAIL:
            tpm2_tool_output ("TPM_PT_HR_LOADED_AVAIL:      0x%08x\n", value);
            break;
        case TPM_PT_HR_ACTIVE:
            tpm2_tool_output ("TPM_PT_HR_ACTIVE:            0x%08x\n", value);
            break;
        case TPM_PT_HR_ACTIVE_AVAIL:
            tpm2_tool_output ("TPM_PT_HR_ACTIVE_AVAIL:      0x%08x\n", value);
            break;
        case TPM_PT_HR_TRANSIENT_AVAIL:
            tpm2_tool_output ("TPM_PT_HR_TRANSIENT_AVAIL:   0x%08x\n", value);
            break;
        case TPM_PT_HR_PERSISTENT:
            tpm2_tool_output ("TPM_PT_HR_PERSISTENT:        0x%08x\n", value);
            break;
        case TPM_PT_HR_PERSISTENT_AVAIL:
            tpm2_tool_output ("TPM_PT_HR_PERSISTENT_AVAIL:  0x%08x\n", value);
            break;
        case TPM_PT_NV_COUNTERS:
            tpm2_tool_output ("TPM_PT_NV_COUNTERS:          0x%08x\n", value);
            break;
        case TPM_PT_NV_COUNTERS_AVAIL:
            tpm2_tool_output ("TPM_PT_NV_COUNTERS_AVAIL:    0x%08x\n", value);
            break;
        case TPM_PT_ALGORITHM_SET:
            tpm2_tool_output ("TPM_PT_ALGORITHM_SET:        0x%08x\n", value);
            break;
        case TPM_PT_LOADED_CURVES:
            tpm2_tool_output ("TPM_PT_LOADED_CURVES:        0x%08x\n", value);
            break;
        case TPM_PT_LOCKOUT_COUNTER:
            tpm2_tool_output ("TPM_PT_LOCKOUT_COUNTER:      0x%08x\n", value);
            break;
        case TPM_PT_MAX_AUTH_FAIL:
            tpm2_tool_output ("TPM_PT_MAX_AUTH_FAIL:        0x%08x\n", value);
            break;
        case TPM_PT_LOCKOUT_INTERVAL:
            tpm2_tool_output ("TPM_PT_LOCKOUT_INTERVAL:     0x%08x\n", value);
            break;
        case TPM_PT_LOCKOUT_RECOVERY:
            tpm2_tool_output ("TPM_PT_LOCKOUT_RECOVERY:     0x%08x\n", value);
            break;
        case TPM_PT_NV_WRITE_RECOVERY:
            tpm2_tool_output ("TPM_PT_NV_WRITE_RECOVERY:    0x%08x\n", value);
            break;
        case TPM_PT_AUDIT_COUNTER_0:
            tpm2_tool_output ("TPM_PT_AUDIT_COUNTER_0:      0x%08x\n", value);
            break;
        case TPM_PT_AUDIT_COUNTER_1:
            tpm2_tool_output ("TPM_PT_AUDIT_COUNTER_1:      0x%08x\n", value);
            break;
        default:
            LOG_ERR("Unknown property:   0x%08x\n", properties[i].property);
            break;
        }
    }
}
/*
 * Print data about TPM_ALG_ID in human readable form.
 */
void
dump_algorithm_properties (TPM_ALG_ID       id,
                           TPMA_ALGORITHM   alg_attrs)
{
    const char *id_name = tpm2_alg_util_algtostr(id);
    id_name = id_name ? id_name : "unknown";

    tpm2_tool_output ("TPMA_ALGORITHM for ALG_ID: 0x%x - %s\n", id, id_name);
    tpm2_tool_output ("  asymmetric: %s\n", prop_str (alg_attrs.asymmetric));
    tpm2_tool_output ("  symmetric:  %s\n", prop_str (alg_attrs.symmetric));
    tpm2_tool_output ("  hash:       %s\n", prop_str (alg_attrs.hash));
    tpm2_tool_output ("  object:     %s\n", prop_str (alg_attrs.object));
    tpm2_tool_output ("  reserved:   0x%x\n", alg_attrs.reserved1);
    tpm2_tool_output ("  signing:    %s\n", prop_str (alg_attrs.signing));
    tpm2_tool_output ("  encrypting: %s\n", prop_str (alg_attrs.encrypting));
    tpm2_tool_output ("  method:     %s\n", prop_str (alg_attrs.method));
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
        { TPM_CC_NV_UndefineSpaceSpecial, "nv" },
        { TPM_CC_EvictControl, "evictcontrol" },
        { TPM_CC_HierarchyControl, "hierarchycontrol" },
        { TPM_CC_NV_UndefineSpace, "nv" },
        { TPM_CC_ChangeEPS, "changeeps" },
        { TPM_CC_ChangePPS, "changepps" },
        { TPM_CC_Clear, "clear" },
        { TPM_CC_ClearControl, "clearcontrol" },
        { TPM_CC_ClockSet, "clockset" },
        { TPM_CC_HierarchyChangeAuth, "hierarchychangeauth" },
        { TPM_CC_NV_DefineSpace, "nv" },
        { TPM_CC_PCR_Allocate, "pcr" },
        { TPM_CC_PCR_SetAuthPolicy, "pcr" },
        { TPM_CC_PP_Commands, "pp" },
        { TPM_CC_SetPrimaryPolicy, "setprimarypolicy" },
        { TPM_CC_FieldUpgradeStart, "fieldupgradestart" },
        { TPM_CC_ClockRateAdjust, "clockrateadjust" },
        { TPM_CC_CreatePrimary, "createprimary" },
        { TPM_CC_NV_GlobalWriteLock, "nv" },
        { TPM_CC_GetCommandAuditDigest, "getcommandauditdigest" },
        { TPM_CC_NV_Increment, "nv" },
        { TPM_CC_NV_SetBits, "nv" },
        { TPM_CC_NV_Extend, "nv" },
        { TPM_CC_NV_Write, "nv" },
        { TPM_CC_NV_WriteLock, "nv" },
        { TPM_CC_DictionaryAttackLockReset, "dictionaryattacklockreset" },
        { TPM_CC_DictionaryAttackParameters, "dictionaryattackparameters" },
        { TPM_CC_NV_ChangeAuth, "nv" },
        { TPM_CC_PCR_Event, "pcr" },
        { TPM_CC_PCR_Reset, "pcr" },
        { TPM_CC_SequenceComplete, "sequencecomplete" },
        { TPM_CC_SetAlgorithmSet, "setalgorithmset" },
        { TPM_CC_SetCommandCodeAuditStatus, "setcommandcodeauditstatus" },
        { TPM_CC_FieldUpgradeData, "fieldupgradedata" },
        { TPM_CC_Startup, "startup" },
        { TPM_CC_Shutdown, "shutdown" },
        { TPM_CC_StirRandom, "stirrandom" },
        { TPM_CC_ActivateCredential, "activatecredential" },
        { TPM_CC_Certify, "certify" },
        { TPM_CC_PolicyNV, "policynv" },
        { TPM_CC_CertifyCreation, "certifycreation" },
        { TPM_CC_Duplicate, "duplicate" },
        { TPM_CC_GetTime, "gettime" },
        { TPM_CC_GetSessionAuditDigest, "getsessionauditdigest" },
        { TPM_CC_NV_Read, "nv" },
        { TPM_CC_NV_ReadLock, "nv" },
        { TPM_CC_ObjectChangeAuth, "objectchangeauth" },
        { TPM_CC_PolicySecret, "policysecret" },
        { TPM_CC_Rewrap, "rewrap" },
        { TPM_CC_Create, "create" },
        { TPM_CC_ECDH_ZGen, "ecdh" },
        { TPM_CC_HMAC, "hmac" },
        { TPM_CC_Import, "import" },
        { TPM_CC_Load, "load" },
        { TPM_CC_Quote, "quote" },
        { TPM_CC_RSA_Decrypt, "rsa" },
        { TPM_CC_HMAC_Start, "hmac" },
        { TPM_CC_SequenceUpdate, "sequenceupdate" },
        { TPM_CC_Sign, "sign" },
        { TPM_CC_Unseal, "unseal" },
        { TPM_CC_PolicySigned, "policysigned" },
        { TPM_CC_ContextLoad, "contextload" },
        { TPM_CC_ContextSave, "contextsave" },
        { TPM_CC_ECDH_KeyGen, "ecdh" },
        { TPM_CC_EncryptDecrypt, "encryptdecrypt" },
        { TPM_CC_FlushContext, "flushcontext" },
        { TPM_CC_LoadExternal, "loadexternal" },
        { TPM_CC_MakeCredential, "makecredential" },
        { TPM_CC_NV_ReadPublic, "nv" },
        { TPM_CC_PolicyAuthorize, "policyauthorize" },
        { TPM_CC_PolicyAuthValue, "policyauthvalue" },
        { TPM_CC_PolicyCommandCode, "policycommandcode" },
        { TPM_CC_PolicyCounterTimer, "policycountertimer" },
        { TPM_CC_PolicyCpHash, "policycphash" },
        { TPM_CC_PolicyLocality, "policylocality" },
        { TPM_CC_PolicyNameHash, "policynamehash" },
        { TPM_CC_PolicyOR, "policyor" },
        { TPM_CC_PolicyTicket, "policyticket" },
        { TPM_CC_ReadPublic, "readpublic" },
        { TPM_CC_RSA_Encrypt, "rsa" },
        { TPM_CC_StartAuthSession, "startauthsession" },
        { TPM_CC_VerifySignature, "verifysignature" },
        { TPM_CC_ECC_Parameters, "ecc" },
        { TPM_CC_FirmwareRead, "firmwareread" },
        { TPM_CC_GetCapability, "getcapability" },
        { TPM_CC_GetRandom, "getrandom" },
        { TPM_CC_Hash, "hash" },
        { TPM_CC_PCR_Read, "pcr" },
        { TPM_CC_PolicyPCR, "policypcr" },
        { TPM_CC_PolicyRestart, "policyrestart" },
        { TPM_CC_ReadClock, "readclock" },
        { TPM_CC_PCR_Extend, "pcr" },
        { TPM_CC_PCR_SetAuthValue, "pcr" },
        { TPM_CC_NV_Certify, "nv" },
        { TPM_CC_EventSequenceComplete, "eventsequencecomplete" },
        { TPM_CC_HashSequenceStart, "hashsequencestart" },
        { TPM_CC_PolicyPhysicalPresence, "policyphysicalpresence" },
        { TPM_CC_PolicyDuplicationSelect, "policyduplicationselect" },
        { TPM_CC_PolicyGetDigest, "policygetdigest" },
        { TPM_CC_Commit, "commit" },
        { TPM_CC_PolicyPassword, "policypassword" },
        { TPM_CC_ZGen_2Phase, "zgen" },
        { TPM_CC_EC_Ephemeral, "ec" },
        { TPM_CC_PolicyNvWritten, "policynvwritten" }
    };

    if (cc < TPM_CC_FIRST || cc > TPM_CC_LAST) {
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
    tpm2_tool_output ("TPMA_CC: 0x%08x\n", tpma_cc.val);
    tpm2_tool_output ("  name: %s\n", cc_to_str(tpma_cc.commandIndex));
    tpm2_tool_output ("  commandIndex: 0x%x\n", tpma_cc.commandIndex);
    tpm2_tool_output ("  reserved1:    0x%x\n", tpma_cc.reserved1);
    tpm2_tool_output ("  nv:           %s\n",   prop_str (tpma_cc.nv));
    tpm2_tool_output ("  extensive:    %s\n",   prop_str (tpma_cc.extensive));
    tpm2_tool_output ("  flushed:      %s\n",   prop_str (tpma_cc.flushed));
    tpm2_tool_output ("  cHandles:     0x%x\n", tpma_cc.cHandles);
    tpm2_tool_output ("  rHandle:      %s\n",   prop_str (tpma_cc.rHandle));
    tpm2_tool_output ("  V:            %s\n",   prop_str (tpma_cc.V));
    tpm2_tool_output ("  Res:          0x%x\n", tpma_cc.Res);
}
/*
 * Iterate over an array of TPM_ECC_CURVEs and dump out a human readable
 * representation of each array member.
 */
void
dump_ecc_curves (TPM_ECC_CURVE     curve[],
                 UINT32            count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        switch(curve[i]) {
            case TPM_ECC_NIST_P192:
                tpm2_tool_output ("TPM_ECC_NIST_P192 (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_NIST_P224:
                tpm2_tool_output ("TPM_ECC_NIST_P224 (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_NIST_P256:
                tpm2_tool_output ("TPM_ECC_NIST_P256 (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_NIST_P384:
                tpm2_tool_output ("TPM_ECC_NIST_P384 (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_NIST_P521:
                tpm2_tool_output ("TPM_ECC_NIST_P521 (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_BN_P256:
                tpm2_tool_output ("TPM_ECC_BN_P256   (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_BN_P638:
                tpm2_tool_output ("TPM_ECC_BN_P638   (0x%04x)\n", curve[i]);
		break;
            case TPM_ECC_SM2_P256:
                tpm2_tool_output ("TPM_ECC_SM2_P256 (0x%04x)\n", curve[i]);
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
dump_handles (TPM_HANDLE     handles[],
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
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Failed to GetCapability: capability: 0x%x, property: 0x%x, "
                 "TSS2_RC: 0x%x\n", options.capability, options.property, rc);
    } else if (more_data == YES) {
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
    case TPM_CAP_ALGS:
        dump_algorithms (capabilities->algorithms.algProperties,
                         capabilities->algorithms.count);
        break;
    case TPM_CAP_COMMANDS:
        dump_command_attr_array (capabilities->command.commandAttributes,
                                 capabilities->command.count);
        break;
    case TPM_CAP_TPM_PROPERTIES:
        switch (options.property) {
        case PT_FIXED:
            dump_tpm_properties_fixed (capabilities->tpmProperties.tpmProperty,
                                       capabilities->tpmProperties.count);
            break;
        case PT_VAR:
            dump_tpm_properties_var (capabilities->tpmProperties.tpmProperty,
                                     capabilities->tpmProperties.count);
            break;
        default:
            return 1;
        }
        break;
    case TPM_CAP_ECC_CURVES:
	dump_ecc_curves (capabilities->eccCurves.eccCurves,
                         capabilities->eccCurves.count);
	break;
    case TPM_CAP_HANDLES:
        switch (options.property & HR_RANGE_MASK) {
        case HR_TRANSIENT:
        case HR_PERSISTENT:
        case HR_PERMANENT:
        case HR_PCR:
        case HR_NV_INDEX:
        case TPM_HT_LOADED_SESSION << HR_SHIFT:
        case TPM_HT_SAVED_SESSION << HR_SHIFT:
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

    tpm2_option_flags empty_flags = tpm2_option_flags_init(0);
    *opts = tpm2_options_new("c:", ARRAY_LEN(topts), topts,
            on_option, NULL, empty_flags);

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
    if (rc != TSS2_RC_SUCCESS)
        return 1;

    dump_tpm_capability(&capability_data.data);
    return 0;
}
