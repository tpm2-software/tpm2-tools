/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct clear_ctx clear_ctx;
struct clear_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

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

static clear_ctx ctx = {
    .auth_hierarchy.ctx_path = "l",
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc clear(ESYS_CONTEXT *ectx) {

    return tpm2_clear(ectx, &ctx.auth_hierarchy.object, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
}


static tool_rc process_output(ESYS_CONTEXT *ectx) {

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

    return rc;
}


static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_L | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid lockout authorization");
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
        ctx.auth_hierarchy.object.session,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    if (!ctx.is_command_dispatch) {
        LOG_WARN("Generating cpHash. Exiting without executing clear.");
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify a single auth value");
        return false;
    }

    /*
     * empty auth
     */
    if (!argc) {
        return true;
    }

    ctx.auth_hierarchy.auth_str = argv[0];

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-hierarchy", required_argument, 0, 'c' },
        { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("c:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
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
    rc = clear(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("clear", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
