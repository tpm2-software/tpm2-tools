//**********************************************************************;
// Copyright (c) 2016-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <inttypes.h>
#include <stdbool.h>

#include "log.h"
#include "rc-decode.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#define TPM2_RC_MAX 0xffffffff

static bool str_to_tpm_rc(const char *rc_str, TSS2_RC *rc) {
    uintmax_t rc_read = 0;
    char *end_ptr = NULL;

    rc_read = strtoumax(rc_str, &end_ptr, 0);
    if (rc_read > TPM2_RC_MAX) {
        LOG_ERR("invalid TSS2_RC");
        return false;
    }

    /* apply the TPM2_RC_MAX mask to the possibly larger uintmax_t */
    *rc = rc_read & TPM2_RC_MAX;

    return true;
}

/* Dump the hex, identifier and description for the format zero / VER1 error
 * provided in TSS2_RC parameter.
 */
static int print_tpm_rc_format_zero(TSS2_RC rc) {
    TSS2_RC rc_tmp;
    tpm2_rc_entry_t *entry;

    rc_tmp = tpm2_rc_get_code_7bit(rc);
    if (tpm2_rc_is_vendor_defined(rc)) {
        LOG_ERR("vendor defined TSS2_RCs are not supported");
        return -1;
    } else if (tpm2_rc_is_warning_code(rc)) {
        entry = tpm2_get_warn_entry(rc_tmp);
        if (entry)
            tpm2_tool_output("format 0 warning code\n  hex: 0x%02x\n  name: %s\n  "
                    "description: %s\n", rc_tmp, entry->name,
                    entry->description);
        else
            tpm2_tool_output("failed to decode TSS2_RC warning: 0x%x\n", rc_tmp);
    } else if (tpm2_rc_is_error_code(rc)) {
        entry = tpm2_get_fmt0_entry(rc_tmp);
        if (entry)
            tpm2_tool_output("format 0 error code\n  hex: 0x%02x\n  name: %s\n  "
                    "description: %s\n", rc_tmp, entry->name,
                    entry->description);
        else
            tpm2_tool_output("failed to decode TSS2_RC error: 0x%02x\n", rc_tmp);
    } else if (tpm2_rc_is_tpm12(rc_tmp)) {
        LOG_ERR("version 1.2 TSS2_RCs are not supported");
        return -1;
    } else {
        LOG_ERR("Unknown TSS2_RC format");
        return -1;
    }
    /* decode warning / error code */
    return 0;
}
/* Dump the hex, identifier and description for the format one / FMT1 error
 * as well as the parameter, handle or session data.
 */
static int print_tpm_rc_format_one(TSS2_RC rc) {
    TSS2_RC rc_tmp;
    tpm2_rc_entry_t *entry;

    tpm2_tool_output("format 1 error code\n");
    rc_tmp = tpm2_rc_get_code_6bit(rc);
    tpm2_tool_output("  hex: 0x%02x\n", rc_tmp);
    /* decode error message */
    entry = tpm2_get_fmt1_entry(rc_tmp);
    if (!entry) {
        tpm2_tool_output("Unknown TSS2_RC\n");
        return -1;
    }
    tpm2_tool_output("  identifier: %s\n  description: %s\n", entry->name,
            entry->description);
    /* decode parameter / handle / session number */
    if (tpm2_rc_is_error_code_with_parameter(rc)) {
        rc_tmp = tpm2_rc_get_parameter_number(rc);
        entry = tpm2_get_parameter_entry(rc_tmp);
        if (!entry) {
            tpm2_tool_output("Unknown TSS2_RC parameter number: 0x%03x\n", rc_tmp);
            return -1;
        }
        tpm2_tool_output("parameter\n  hex: 0x%03x\n  identifier:  %s\n  "
                "description:  %s\n", rc_tmp, entry->name, entry->description);
    } else if (tpm2_rc_is_error_code_with_handle(rc)) {
        rc_tmp = tpm2_rc_get_handle_number(rc);
        entry = tpm2_get_handle_entry(rc_tmp);
        if (!entry) {
            tpm2_tool_output("Unkonwn TSS2_RC handle number: 0x%03x\n", rc_tmp);
            return -1;
        }
        tpm2_tool_output("handle\n  hex:0x%03x\n  identifier:  %s\n  "
                "description:  %s\n", rc_tmp, entry->name, entry->description);
    } else if (tpm2_rc_is_error_code_with_session(rc)) {
        rc_tmp = tpm2_rc_get_session_number(rc);
        entry = tpm2_get_session_entry(rc_tmp);
        if (!entry) {
            tpm2_tool_output("Unknown TSS2_RC session number: 0x%03x\n", rc_tmp);
            return -1;
        }
        tpm2_tool_output("session\n  hex: 0x%03x\n  identifier: %s\n  "
                "description:  %s\n", rc_tmp, entry->name, entry->description);
    }

    return 0;
}
/* Dump the hex, identifier and description for the TSS defined layer
 * indicator in the provided TSS2_RC.
 */
static int print_tpm_rc_tss_layer(TSS2_RC rc) {
    TSS2_RC rc_tmp;
    tpm2_rc_entry_t *entry;
    int ret;

    rc_tmp = tpm2_rc_get_layer(rc);
    /* Currently no entry for 0x0 layer, assume it's directly from the TPM? */
    tpm2_tool_output("error layer\n  hex: 0x%x\n", rc_tmp);
    entry = tpm2_get_layer_entry(rc_tmp);
    if (entry) {
        tpm2_tool_output("  identifier: %s\n  description: %s\n", entry->name,
                entry->description);
        ret = 0;
    } else {
        tpm2_tool_output("failed to decode TSS2_RC layer: 0x%x\n", rc_tmp);
        ret = -1;
    }

    return ret;
}
/* Dump the hex, identifier string and description for the TSS defined
 * base error code in the provided TSS2_RC.
 */
static int print_tpm_rc_tss_error_code(TSS2_RC rc) {
    TSS2_RC rc_tmp;
    tpm2_rc_entry_t *entry;
    int ret;

    entry = tpm2_get_tss_base_rc_entry(rc);
    if (entry) {
        tpm2_tool_output("base error code\n  identifier: %s\n  description: %s\n",
                entry->name, entry->description);
        ret = 0;
    } else {
        rc_tmp = tpm2_rc_get_tss_err_code(rc);
        tpm2_tool_output("failed to decode TSS2_RC error code: 0x%x\n", rc_tmp);
        ret = -1;
    }

    return ret;
}
/* Top level function to dump human readable data about TSS2_RCs as defined
 * in the TPM2 Part 2: Structures, Table 17..
 */
static int print_tpm_rc_tpm_error_code(TSS2_RC rc) {
    if (tpm2_rc_is_format_zero(rc))
        print_tpm_rc_format_zero(rc);
    else if (tpm2_rc_is_format_one(rc))
        print_tpm_rc_format_one(rc);
    else {
        LOG_ERR("Unknown TSS2_RC format");
        return -1;
    }
    return 0;
}
/* Top level function to dump human readable data about TSS2_RCs.
 */
bool print_tpm_rc(TSS2_RC rc) {

    /* Determine which layer in the stack produced the error */
    TSS2_RC rc_tmp = tpm2_rc_get_layer(rc);
    int ret = print_tpm_rc_tss_layer(rc);
    if (ret) {
        return false;
    }

    switch (rc_tmp) {
    case TSS2_SYS_RC_LAYER:
    case TSS2_TCTI_RC_LAYER:
    case TSS2_RESMGR_RC_LAYER:
        ret = print_tpm_rc_tss_error_code(rc);
        break;
    case TSS2_MU_RC_LAYER:
    case TSS2_RESMGR_TPM_RC_LAYER:
    case TSS2_TPM_RC_LAYER:
        ret = print_tpm_rc_tpm_error_code(rc);
        break;
    default:
        break;
    }

    return ret == 0;
}

static char *rc_str;

static bool on_arg(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Expected 1 rc code, got: %d", argc);
    }

    rc_str = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL,
            NULL, on_arg, TPM2_OPTIONS_SHOW_USAGE|TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(sapi_context);

    TSS2_RC rc;

    if (!rc_str) {
        LOG_ERR("Expected a single rc value argument, got none.");
        return 1;
    }

    bool result = str_to_tpm_rc(rc_str, &rc);
    if (!result) {
        return 1;
    }

    result = print_tpm_rc(rc);
    return result != true;
}
