/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
typedef struct tpm_geteccparameters_ctx tpm_geteccparameters_ctx;
struct tpm_geteccparameters_ctx {
    /*
     * Inputs
     */
    TPMI_ECC_CURVE curve_id;

    /*
     * Outputs
     */
    TPMS_ALGORITHM_DETAIL_ECC *parameters;
    const char *ecc_parameters_path;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

};

static tpm_geteccparameters_ctx ctx = {
    .curve_id = TPM2_ECC_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc geteccparameters(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_geteccparameters(ectx, ctx.curve_id, &ctx.parameters,
        &ctx.cp_hash, ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed TPM2_CC_ECC_Parameters");
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
    is_file_op_success = files_save_ecc_details(ctx.parameters,
        ctx.ecc_parameters_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the ECC pub key");
        return tool_rc_general_error;
    }

    return tool_rc_success;
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

    if (!ctx.ecc_parameters_path) {
        LOG_ERR("Invalid path specified for saving the ECC parameters.");
        return tool_rc_option_error;
    }

    if (ctx.curve_id == TPM2_ECC_NONE) {
        LOG_ERR("Invalid/ unspecified ECC curve");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.ecc_parameters_path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
    break;
    };

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify a single argument for curveID");
        return false;
    }

    bool result = true;
    TPM2B_PUBLIC algorithm = { 0 };
    if (!tpm2_alg_util_handle_ext_alg(argv[0], &algorithm)) {
        result = false;
    }

    if (algorithm.publicArea.type != TPM2_ALG_ECC) {
        result = false;
    }

    if (!result) {
        LOG_ERR("Invalid/unsupported ECC curve: %s", argv[0]);
        return false;
    }

    ctx.curve_id = algorithm.publicArea.parameters.eccDetail.curveID;

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "output",  required_argument, 0, 'o' },
      { "cphash",  required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("o:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != 0;
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
    rc = geteccparameters(ectx);
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

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("geteccparameters", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
