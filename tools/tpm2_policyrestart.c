/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"
#include "files.h"

#define MAX_SESSIONS 3
typedef struct tpm2_policyreset_ctx tpm2_policyreset_ctx;
struct tpm2_policyreset_ctx {
    /*
     * Inputs
     */
    char *path;
    tpm2_session *session;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm2_policyreset_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc policyrestart(ESYS_CONTEXT *ectx) {

    return tpm2_session_restart(ectx, ctx.session, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
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
    tool_rc rc = tpm2_session_restore(ectx, ctx.path, false, &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

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
        ctx.session,
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

    if (!ctx.path) {
        LOG_ERR("Must specify -S session file.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'S':
        ctx.path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "session", required_argument,  NULL, 'S' },
        { "cphash",  required_argument,  NULL,  0  },

    };

    *opts = tpm2_options_new("S:", ARRAY_LEN(topts), topts, on_option,
        NULL, 0);

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
    rc = policyrestart(ectx);
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
    return tpm2_session_close(&ctx.session);

    /*
     * 3. Close auxiliary sessions
     */
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policyrestart", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
