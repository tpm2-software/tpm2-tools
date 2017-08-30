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
#include <stdio.h>
#include <getopt.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

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
        .capability_string = "algorithms",
        .capability        = TPM_CAP_ALGS,
        .property          = TPM_ALG_FIRST,
        .count             = MAX_ALG_LIST_SIZE,
    },
    {
        .capability_string = "commands",
        .capability        = TPM_CAP_COMMANDS,
        .property          = TPM_CC_FIRST,
        .count             = MAX_CAP_CC,
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
/*
 * This function takes a capability_opts_t structure as a parameter. It
 * uses the 'param' field in this structure to locate the same string in
 * the capability_map array and then populates the 'capability' and
 * 'property' fields of the capability_opts_t structure with the appropriate
 * values from the capability_map.
 * Return values:
 * 0 - the function executed normally.
 * 1 - the parameter 'param' in the capability_opts_t structure is NULL.
 * 2 - no matching entry found in capability_map.
 */
int
sanity_check_capability_opts (capability_opts_t *capability_opts)
{

    if (capability_opts->capability_string == NULL) {
        fprintf (stderr, "missing capability string, see --help\n");
        return 2;
    }

    size_t i;
    for (i = 0; i < CAPABILITY_MAP_COUNT; ++i) {
        int cmp = strncmp (capability_map [i].capability_string,
                           capability_opts->capability_string,
                           strlen (capability_map [i].capability_string));
        if (cmp == 0) {
            capability_opts->capability = capability_map [i].capability;
            capability_opts->property   = capability_map [i].property;
            capability_opts->count      = capability_map [i].count;
            return 0;
        }
    }
    fprintf (stderr,
             "invalid capability string: %s, see --help\n",
             capability_opts->capability_string);
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
printf_tpma_modes (TPMA_MODES    modes)
{
    printf ("TPM_PT_MODES: 0x%08x\n", modes.val);
    if (modes.FIPS_140_2)
        printf ("  TPMA_MODES_FIPS_140_2\n");
    if (modes.reserved1)
        printf ("  TPMA_MODES_RESERVED1 (these bits shouldn't be set)\n");
}
/*
 * Print string representation of the TPMA_PERMANENT attributes.
 */
void
dump_permanent_attrs (TPMA_PERMANENT attrs)
{
    printf ("TPM_PT_PERSISTENT:\n");
    printf ("  ownerAuthSet:              %s\n", prop_str (attrs.ownerAuthSet));
    printf ("  endorsementAuthSet:        %s\n", prop_str (attrs.endorsementAuthSet));
    printf ("  lockoutAuthSet:            %s\n", prop_str (attrs.lockoutAuthSet));
    printf ("  reserved1:                 %s\n", prop_str (attrs.reserved1));
    printf ("  disableClear:              %s\n", prop_str (attrs.disableClear));
    printf ("  inLockout:                 %s\n", prop_str (attrs.inLockout));
    printf ("  tpmGeneratedEPS:           %s\n", prop_str (attrs.tpmGeneratedEPS));
    printf ("  reserved2:                 %s\n", prop_str (attrs.reserved2));
}
/*
 * Print string representations of the TPMA_STARTUP_CLEAR attributes.
 */
void
dump_startup_clear_attrs (TPMA_STARTUP_CLEAR attrs)
{
    printf ("TPM_PT_STARTUP_CLEAR:\n");
    printf ("  phEnable:                  %s\n", prop_str (attrs.phEnable));
    printf ("  shEnable:                  %s\n", prop_str (attrs.shEnable));
    printf ("  ehEnable:                  %s\n", prop_str (attrs.ehEnable));
    printf ("  phEnableNV:                %s\n", prop_str (attrs.phEnableNV));
    printf ("  reserved1:                 %s\n", prop_str (attrs.reserved1));
    printf ("  orderly:                   %s\n", prop_str (attrs.orderly));
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
            printf ("TPM_PT_FAMILY_INDICATOR:\n"
                    "  as UINT32:                0x08%x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_LEVEL:
            printf ("TPM_PT_LEVEL:               %d\n", value);
            break;
        case TPM_PT_REVISION:
            printf ("TPM_PT_REVISION:            %.2f\n", (float)value / 100);
            break;
        case TPM_PT_DAY_OF_YEAR:
            printf ("TPM_PT_DAY_OF_YEAR:         0x%08x\n", value);
            break;
        case TPM_PT_YEAR:
            printf ("TPM_PT_YEAR:                0x%08x\n", value);
            break;
        case TPM_PT_MANUFACTURER:
            printf ("TPM_PT_MANUFACTURER:        0x%08x\n", value);
            break;
        case TPM_PT_VENDOR_STRING_1:
            get_uint32_as_chars (value, buf);
            printf ("TPM_PT_VENDOR_STRING_1:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_STRING_2:
            get_uint32_as_chars (value, buf);
            printf ("TPM_PT_VENDOR_STRING_2:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_STRING_3:
            get_uint32_as_chars (value, buf);
            printf ("TPM_PT_VENDOR_STRING_3:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_STRING_4:
            get_uint32_as_chars (value, buf);
            printf ("TPM_PT_VENDOR_STRING_4:\n"
                    "  as UINT32:                0x%08x\n"
                    "  as string:                \"%s\"\n",
                    value,
                    buf);
            break;
        case TPM_PT_VENDOR_TPM_TYPE:
            printf ("TPM_PT_VENDOR_TPM_TYPE:     0x%08x\n", value);
            break;
        case TPM_PT_FIRMWARE_VERSION_1:
            printf ("TPM_PT_FIRMWARE_VERSION_1:  0x%08x\n", value);
            break;
        case TPM_PT_FIRMWARE_VERSION_2:
            printf ("TPM_PT_FIRMWARE_VERSION_2:  0x%08x\n", value);
            break;
        case TPM_PT_INPUT_BUFFER:
            printf ("TPM_PT_INPUT_BUFFER:        0x%08x\n", value);
            break;
        case TPM_PT_HR_TRANSIENT_MIN:
            printf ("TPM_PT_HR_TRANSIENT_MIN:    0x%08x\n", value);
            break;
        case TPM_PT_HR_PERSISTENT_MIN:
            printf ("TPM_PT_HR_PERSISTENT_MIN:   0x%08x\n", value);
            break;
        case TPM_PT_HR_LOADED_MIN:
            printf ("TPM_PT_HR_LOADED_MIN:       0x%08x\n", value);
            break;
        case TPM_PT_ACTIVE_SESSIONS_MAX:
            printf ("TPM_PT_ACTIVE_SESSIONS_MAX: 0x%08x\n", value);
            break;
        case TPM_PT_PCR_COUNT:
            printf ("TPM_PT_PCR_COUNT:           0x%08x\n", value);
            break;
        case TPM_PT_PCR_SELECT_MIN:
            printf ("TPM_PT_PCR_SELECT_MIN:      0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_GAP_MAX:
            printf ("TPM_PT_CONTEXT_GAP_MAX:     0x%08x\n", value);
            break;
        case TPM_PT_NV_COUNTERS_MAX:
            printf ("TPM_PT_NV_COUNTERS_MAX:     0x%08x\n", value);
            break;
        case TPM_PT_NV_INDEX_MAX:
            printf ("TPM_PT_NV_INDEX_MAX:        0x%08x\n", value);
            break;
        case TPM_PT_MEMORY:
            printf ("TPM_PT_MEMORY:              0x%08x\n", value);
            break;
        case TPM_PT_CLOCK_UPDATE:
            printf ("TPM_PT_CLOCK_UPDATE:        0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_HASH: /* this may be a TPM_ALG_ID type */
            printf ("TPM_PT_CONTEXT_HASH:        0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_SYM: /* this is a TPM_ALG_ID type */
            printf ("TPM_PT_CONTEXT_SYM:         0x%08x\n", value);
            break;
        case TPM_PT_CONTEXT_SYM_SIZE:
            printf ("TPM_PT_CONTEXT_SYM_SIZE:    0x%08x\n", value);
            break;
        case TPM_PT_ORDERLY_COUNT:
            printf ("TPM_PT_ORDERLY_COUNT:       0x%08x\n", value);
            break;
        case TPM_PT_MAX_COMMAND_SIZE:
            printf ("TPM_PT_MAX_COMMAND_SIZE:    0x%08x\n", value);
            break;
        case TPM_PT_MAX_RESPONSE_SIZE:
            printf ("TPM_PT_MAX_RESPONSE_SIZE:   0x%08x\n", value);
            break;
        case TPM_PT_MAX_DIGEST:
            printf ("TPM_PT_MAX_DIGEST:          0x%08x\n", value);
            break;
        case TPM_PT_MAX_OBJECT_CONTEXT:
            printf ("TPM_PT_MAX_OBJECT_CONTEXT:  0x%08x\n", value);
            break;
        case TPM_PT_MAX_SESSION_CONTEXT:
            printf ("TPM_PT_MAX_SESSION_CONTEXT: 0x%08x\n", value);
            break;
        case TPM_PT_PS_FAMILY_INDICATOR:
            printf ("TPM_PT_PS_FAMILY_INDICATOR: 0x%08x\n", value);
            break;
        case TPM_PT_PS_LEVEL:
            printf ("TPM_PT_PS_LEVEL:            0x%08x\n", value);
            break;
        case TPM_PT_PS_REVISION:
            printf ("TPM_PT_PS_REVISION:         0x%08x\n", value);
            break;
        case TPM_PT_PS_DAY_OF_YEAR:
            printf ("TPM_PT_PS_DAY_OF_YEAR:      0x%08x\n", value);
            break;
        case TPM_PT_PS_YEAR:
            printf ("TPM_PT_PS_YEAR:             0x%08x\n", value);
            break;
        case TPM_PT_SPLIT_MAX:
            printf ("TPM_PT_SPLIT_MAX:           0x%08x\n", value);
            break;
        case TPM_PT_TOTAL_COMMANDS:
            printf ("TPM_PT_TOTAL_COMMANDS:      0x%08x\n", value);
            break;
        case TPM_PT_LIBRARY_COMMANDS:
            printf ("TPM_PT_LIBRARY_COMMANDS:    0x%08x\n", value);
            break;
        case TPM_PT_VENDOR_COMMANDS:
            printf ("TPM_PT_VENDOR_COMMANDS:     0x%08x\n", value);
            break;
        case TPM_PT_NV_BUFFER_MAX:
            printf ("TPM_PT_NV_BUFFER_MAX:       0x%08x\n", value);
            break;
        case TPM_PT_MODES:
            printf_tpma_modes ((TPMA_MODES)value);
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
            printf ("TPM_PT_HR_NV_INDEX:          0x%08x\n", value);
            break;
        case TPM_PT_HR_LOADED:
            printf ("TPM_PT_HR_LOADED:            0x%08x\n", value);
            break;
        case TPM_PT_HR_LOADED_AVAIL:
            printf ("TPM_PT_HR_LOADED_AVAIL:      0x%08x\n", value);
            break;
        case TPM_PT_HR_ACTIVE:
            printf ("TPM_PT_HR_ACTIVE:            0x%08x\n", value);
            break;
        case TPM_PT_HR_ACTIVE_AVAIL:
            printf ("TPM_PT_HR_ACTIVE_AVAIL:      0x%08x\n", value);
            break;
        case TPM_PT_HR_TRANSIENT_AVAIL:
            printf ("TPM_PT_HR_TRANSIENT_AVAIL:   0x%08x\n", value);
            break;
        case TPM_PT_HR_PERSISTENT:
            printf ("TPM_PT_HR_PERSISTENT:        0x%08x\n", value);
            break;
        case TPM_PT_HR_PERSISTENT_AVAIL:
            printf ("TPM_PT_HR_PERSISTENT_AVAIL:  0x%08x\n", value);
            break;
        case TPM_PT_NV_COUNTERS:
            printf ("TPM_PT_NV_COUNTERS:          0x%08x\n", value);
            break;
        case TPM_PT_NV_COUNTERS_AVAIL:
            printf ("TPM_PT_NV_COUNTERS_AVAIL:    0x%08x\n", value);
            break;
        case TPM_PT_ALGORITHM_SET:
            printf ("TPM_PT_ALGORITHM_SET:        0x%08x\n", value);
            break;
        case TPM_PT_LOADED_CURVES:
            printf ("TPM_PT_LOADED_CURVES:        0x%08x\n", value);
            break;
        case TPM_PT_LOCKOUT_COUNTER:
            printf ("TPM_PT_LOCKOUT_COUNTER:      0x%08x\n", value);
            break;
        case TPM_PT_MAX_AUTH_FAIL:
            printf ("TPM_PT_MAX_AUTH_FAIL:        0x%08x\n", value);
            break;
        case TPM_PT_LOCKOUT_INTERVAL:
            printf ("TPM_PT_LOCKOUT_INTERVAL:     0x%08x\n", value);
            break;
        case TPM_PT_LOCKOUT_RECOVERY:
            printf ("TPM_PT_LOCKOUT_RECOVERY:     0x%08x\n", value);
            break;
        case TPM_PT_NV_WRITE_RECOVERY:
            printf ("TPM_PT_NV_WRITE_RECOVERY:    0x%08x\n", value);
            break;
        case TPM_PT_AUDIT_COUNTER_0:
            printf ("TPM_PT_AUDIT_COUNTER_0:      0x%08x\n", value);
            break;
        case TPM_PT_AUDIT_COUNTER_1:
            printf ("TPM_PT_AUDIT_COUNTER_1:      0x%08x\n", value);
            break;
        default:
            fprintf (stderr, "Unknown property:   0x%08x\n", properties[i].property);
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

    printf ("TPMA_ALGORITHM for ALG_ID: 0x%x - %s\n", id, id_name);
    printf ("  asymmetric: %s\n", prop_str (alg_attrs.asymmetric));
    printf ("  symmetric:  %s\n", prop_str (alg_attrs.symmetric));
    printf ("  hash:       %s\n", prop_str (alg_attrs.hash));
    printf ("  object:     %s\n", prop_str (alg_attrs.object));
    printf ("  reserved:   0x%x\n", alg_attrs.reserved1);
    printf ("  signing:    %s\n", prop_str (alg_attrs.signing));
    printf ("  encrypting: %s\n", prop_str (alg_attrs.encrypting));
    printf ("  method:     %s\n", prop_str (alg_attrs.method));
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
/*
 * Pretty print the bit fields from the TPMA_CC (UINT32)
 */
void
dump_command_attrs (TPMA_CC tpma_cc)
{
    printf ("TPMA_CC: 0x%08x\n", tpma_cc.val);
    printf ("  commandIndex: 0x%x\n", tpma_cc.commandIndex);
    printf ("  reserved1:    0x%x\n", tpma_cc.reserved1);
    printf ("  nv:           %s\n",   prop_str (tpma_cc.nv));
    printf ("  extensive:    %s\n",   prop_str (tpma_cc.extensive));
    printf ("  flushed:      %s\n",   prop_str (tpma_cc.flushed));
    printf ("  cHandles:     0x%x\n", tpma_cc.cHandles);
    printf ("  rHandle:      %s\n",   prop_str (tpma_cc.rHandle));
    printf ("  V:            %s\n",   prop_str (tpma_cc.V));
    printf ("  Res:          0x%x\n", tpma_cc.Res);
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
 * Query the TPM for TPM capabilities.
 */
TSS2_RC
get_tpm_capability_all (TSS2_SYS_CONTEXT      *sapi_ctx,
                        TPMS_CAPABILITY_DATA  *capability_data,
                        TPM_CAP                capability,
                        UINT32                 property,
                        UINT32                 count)
{
    TSS2_RC                rc;
    TPMI_YES_NO            more_data;

    rc = Tss2_Sys_GetCapability (sapi_ctx,
                                 NULL,
                                 capability,
                                 property,
                                 count,
                                 &more_data,
                                 capability_data,
                                 NULL);
    if (rc != TSS2_RC_SUCCESS)
        fprintf (stderr,
                 "Failed to GetCapability: capability: 0x%x, property: 0x%x, "
                 "TSS2_RC: 0x%x\n", capability, property, rc);
    return rc;
}
/*
 * Get options required by / for this tool.
 * Returns:
 * 0 if we get all of the options we expect.
 * 1 if we encounter an error.
 */
void
get_capability_opts (int                  argc,
                     char                *argv[],
                     capability_opts_t   *capability_opts)
{
    int c = 0, option_index = 0;
    char *arg_str = "c:";
    static struct option long_options [] = {
        {
            .name    = "capability",
            .has_arg = required_argument,
            .flag    = NULL,
            .val     = 'c',
        },
        { .name = NULL, },
    };
    while ((c = getopt_long (argc, argv, arg_str, long_options, &option_index))
           != -1)
    {
        switch (c) {
        case 'c':
            capability_opts->capability_string = optarg;
            break;
        }
    }
}
/*
 * This function is a glorified switch statement. It uses the 'capability'
 * and 'property' parameters to find the right print function for the
 * capabilities in the 'capabilities' parameter.
 * On success it will return 0, if it failes (is unable to find an
 * appropriate print function for the provided 'capability' / 'property'
 * pair) then it will return 1.
 */
static int
dump_tpm_capability (TPMU_CAPABILITIES    *capabilities,
                     TPM_CAP              capability,
                     UINT32               property)
{
    switch (capability) {
    case TPM_CAP_TPM_PROPERTIES:
        switch (property) {
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
    case TPM_CAP_ALGS:
        dump_algorithms (capabilities->algorithms.algProperties,
                         capabilities->algorithms.count);
        break;
    case TPM_CAP_COMMANDS:
        dump_command_attr_array (capabilities->command.commandAttributes,
                                 capabilities->command.count);
        break;
    default:
        return 1;
    }
    return 0;
}
int
execute_tool (int               argc,
              char             *argv[],
              char             *envp[],
              common_opts_t    *opts,
              TSS2_SYS_CONTEXT *sapi_context)
{
    (void) opts;
    (void) envp;

    TSS2_RC              rc;
    TPMS_CAPABILITY_DATA capability_data = TPMS_CAPABILITY_DATA_EMPTY_INIT;
    int ret;
    capability_opts_t options = {
        .capability_string = NULL,
        .capability        = 0,
        .property          = 0,
    };

    get_capability_opts (argc, argv, &options);
    ret = sanity_check_capability_opts (&options);
    if (ret == 1) {
        fprintf (stderr, "Missing capability string. See --help.\n");
        return 1;
    } else if (ret == 2) {
        fprintf (stderr, "Invalid capability string. See --help.\n");
        return 1;
    }
    /* get requested capability from TPM, dump it to stdout */
    rc = get_tpm_capability_all (sapi_context,
                                 &capability_data,
                                 options.capability,
                                 options.property,
                                 options.count);
    if (rc != TSS2_RC_SUCCESS)
        return 1;
    dump_tpm_capability (&capability_data.data,
                         options.capability,
                         options.property);
    return 0;
}
