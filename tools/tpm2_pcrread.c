/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"
#include "files.h"

#define MAX_SESSIONS 3
typedef struct listpcr_context listpcr_context;
struct listpcr_context {
    /*
     * Inputs
     */
    tpm2_convert_pcrs_output_fmt format;
    tpm2_algorithm algs;
    tpm2_pcrs pcrs;
    TPML_PCR_SELECTION pcr_selections;
    TPMI_ALG_HASH selected_algorithm;
    TPMS_CAPABILITY_DATA capdata;

    /*
     * Outputs
     */
    char *output_file_path;
    FILE *output_file;
    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static listpcr_context ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .format = pcrs_output_format_values
};

static tool_rc pcrread(ESYS_CONTEXT *ectx) {

    tool_rc rc = pcr_read_pcr_values(ectx, &ctx.pcr_selections, &ctx.pcrs,
        &ctx.cp_hash, ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed TPM2_CC_PCR_Read"); 
    }

    return rc;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    bool success = pcr_print_values(&ctx.pcr_selections, &ctx.pcrs);
    if (success && ctx.output_file) {
        if (ctx.format == pcrs_output_format_values) {
            success = pcr_fwrite_values(&ctx.pcr_selections, &ctx.pcrs,
                ctx.output_file);
        }

        if (ctx.format == pcrs_output_format_serialized) {
            success = pcr_fwrite_serialized(&ctx.pcr_selections, &ctx.pcrs,
                ctx.output_file);
        }
    }
    return success ? tool_rc_success : tool_rc_general_error;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    tool_rc rc = pcr_get_banks(ectx, &ctx.capdata, &ctx.algs);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = true;
    if (ctx.pcr_selections.count > 0) {
        result = pcr_check_pcr_selection(&ctx.capdata, &ctx.pcr_selections);
    } else {
        result = pcr_init_pcr_selection(&ctx.capdata, &ctx.pcr_selections,
            ctx.selected_algorithm);
    }
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        0,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return tool_rc_success;
}

static tool_rc check_options(void) {

    if (ctx.output_file_path) {
        ctx.output_file = fopen(ctx.output_file_path, "wb+");
        if (!ctx.output_file) {
            LOG_ERR("Could not open output file \"%s\" error: \"%s\"",
                    ctx.output_file_path, strerror(errno));
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.output_file_path = value;
        break;
    case 'F':
        ctx.format = tpm2_convert_pcrs_output_fmt_from_optarg(value);
        if (ctx.format == pcrs_output_format_err) {
            return false;
        }
        break;
        /* no default */
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected PCR list or algorithm selection");
        return false;
    }

    ctx.selected_algorithm = tpm2_alg_util_from_optarg(argv[0],
        tpm2_alg_util_flags_hash);
    if (ctx.selected_algorithm == TPM2_ALG_ERROR) {
        bool res = pcr_parse_selections(argv[0], &ctx.pcr_selections, NULL);
        if (!res) {
            LOG_ERR("Neither algorithm nor pcr list, got: \"%s\"", argv[0]);
            return false;
        }
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
         { "output",         required_argument, NULL, 'o' },
         { "pcrs_format",    required_argument, NULL, 'F' },
         { "cphash",         required_argument, 0,     0  },
     };

    *opts = tpm2_options_new("o:F:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = pcrread(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    if (ctx.output_file) {
        fclose(ctx.output_file);
    }
    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrread", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
