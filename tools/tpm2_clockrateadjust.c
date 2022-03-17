/* SPDX-License-Identifier: BSD-3-Clause */
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#define MAX_SESSIONS 3
typedef struct tpm2_setclock_ctx tpm2_setclock_ctx;
struct tpm2_setclock_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    const char *adjustment;
    TPM2_CLOCK_ADJUST adjust;
    bool is_slower;

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

static tpm2_setclock_ctx ctx = {
    .auth_hierarchy.ctx_path = "o", /* default to owner hierarchy */
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};


static tool_rc clockrateadjust(ESYS_CONTEXT *ectx) {

    return tpm2_clockrateadjust(ectx, &ctx.auth_hierarchy.object, ctx.adjust,
        &ctx.cp_hash, ctx.parameter_hash_algorithm);
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
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
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
    if (ctx.is_slower) {
        ctx.adjust -= strlen(ctx.adjustment);
    } else {
        ctx.adjust += strlen(ctx.adjustment);
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

    size_t len = strlen(ctx.adjustment);
    if (len > 3) {
        LOG_ERR("Expected at most 3 adjustment characters");
        return tool_rc_option_error;
    }

    static const char slower[] = "sss";
    static const char faster[] = "fff";
    ctx.is_slower = ctx.adjustment[0] == 's';
    const char *compare = ctx.is_slower ? slower : faster;

    bool is_equal = !strncmp(ctx.adjustment, compare, len);
    if (!is_equal) {
        LOG_ERR("Adjustment specifier should be consistent, either all "
                "'s' or all 'f' characters got: \"%s\"", ctx.adjustment);
        return tool_rc_option_error;
    }

    LOG_INFO("adjust value: %d", ctx.adjust);

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Can only specify 1 clock rate adjust specifier, got: %d", argc);
        return false;
    }

    ctx.adjustment = argv[0];

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'p':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, 0, 'c' },
        { "auth",      required_argument, 0, 'p' },
        { "cphash",    required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("c:p:", ARRAY_LEN(topts), topts, on_option,
    on_arg, 0);

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
    rc = clockrateadjust(ectx);
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
TPM2_TOOL_REGISTER("clockrateadjust", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
