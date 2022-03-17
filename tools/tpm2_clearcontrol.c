/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct clearcontrol_ctx clearcontrol_ctx;
struct clearcontrol_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPMI_YES_NO disable_clear;

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

static clearcontrol_ctx ctx = {
    .auth_hierarchy.ctx_path = "p",
    .disable_clear = 0,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc clearcontrol(ESYS_CONTEXT *ectx) {

    LOG_INFO("Sending TPM2_ClearControl(%s) disableClear command with auth "
             "handle %s", ctx.disable_clear ? "SET" : "CLEAR",
             ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_PLATFORM ?
                "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");

    return tpm2_clearcontrol(ectx, &ctx.auth_hierarchy.object,
        ctx.disable_clear, &ctx.cp_hash, ctx.parameter_hash_algorithm);
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
    if (!ctx.disable_clear
            && ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_LOCKOUT) {
        LOG_ERR("Only platform hierarchy handle can be specified"
                " for CLEAR operation on disableClear");
        return tool_rc_option_error;
    }

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

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (ctx.disable_clear != 0 && ctx.disable_clear != 1) {
        LOG_ERR("Please use 0|1|s|c as the argument to specify operation");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify single set/clear operation as s|c|0|1.");
        return false;
    }

    if (!argc) {
        LOG_ERR("Disable clear SET/CLEAR operation must be specified.");
        return false;
    }

    if (!strcmp(argv[0], "s")) {
        ctx.disable_clear = 1;
        return true;
    }

    if (!strcmp(argv[0], "c")) {
        ctx.disable_clear = 0;
        return true;
    }

    uint32_t value;
    bool result = tpm2_util_string_to_uint32(argv[0], &value);
    if (!result) {
        LOG_ERR("Please specify 0|1|s|c. Could not convert string, got: \"%s\"",
            argv[0]);
        return false;
    }
    ctx.disable_clear = value;

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",      required_argument, 0, 'C' },
        { "auth",           required_argument, 0, 'P' },
        { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("C:P:", ARRAY_LEN(topts), topts, on_option, on_arg,
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
    rc = clearcontrol(ectx);
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
TPM2_TOOL_REGISTER("clearcontrol", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
