/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
typedef struct dictionarylockout_ctx dictionarylockout_ctx;
struct dictionarylockout_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    UINT32 max_tries;
    UINT32 recovery_time;
    UINT32 lockout_recovery_time;
    bool clear_lockout;
    bool setup_parameters;
    bool is_setup_max_tries;
    bool is_setup_recovery_time;
    bool is_setup_lockoutrecovery_time;

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

static dictionarylockout_ctx ctx = {
    .auth_hierarchy.ctx_path = "l",
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};


static tool_rc dictionarylockout(ESYS_CONTEXT *ectx) {

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * precede parameters setup.
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tool_rc_success;
    if (ctx.clear_lockout) {
        tmp_rc = tpm2_dictionarylockout_reset(ectx, &ctx.auth_hierarchy.object,
            &ctx.cp_hash, ctx.parameter_hash_algorithm);
        if (tmp_rc != tool_rc_success) {
            LOG_ERR("Failed DictionaryLockout Reset");
            rc = tmp_rc;
        }
    }

    if (ctx.setup_parameters) {
        tmp_rc = tpm2_dictionarylockout_setup(ectx, &ctx.auth_hierarchy.object,
            ctx.max_tries, ctx.recovery_time, ctx.lockout_recovery_time,
            &ctx.cp_hash, ctx.parameter_hash_algorithm);
        if (tmp_rc != tool_rc_success) {
            LOG_ERR("Failed DictionaryLockout Setup");
            rc = tmp_rc;
        }
    }

    return rc;
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
            TPM2_HANDLE_FLAGS_L);
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
    if (ctx.setup_parameters && ctx.is_command_dispatch) {
        TPMS_CAPABILITY_DATA *capabilities = 0;
        rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_VAR,
            TPM2_MAX_TPM_PROPERTIES, 0, &capabilities);
        if (rc != tool_rc_success) {
            LOG_ERR("Couldn't read the currently setup parameters.");
            return rc;
        }

        TPMS_TAGGED_PROPERTY *properties = capabilities->data.tpmProperties.tpmProperty;
        size_t count = capabilities->data.tpmProperties.count;

        if (!count) {
            LOG_ERR("Couldn't read the currently setup parameters.");
            free(capabilities);
            return tool_rc_general_error;
        }

        size_t i;
        for (i = 0; i < count; i++) {
            if (!ctx.is_setup_max_tries &&
                properties[i].property == TPM2_PT_MAX_AUTH_FAIL) {
                ctx.max_tries = properties[i].value;
                continue;
            }
            if (!ctx.is_setup_recovery_time &&
                properties[i].property == TPM2_PT_LOCKOUT_INTERVAL) {
                ctx.recovery_time = properties[i].value;
                continue;
            }
            if (!ctx.is_setup_lockoutrecovery_time &&
                properties[i].property == TPM2_PT_LOCKOUT_RECOVERY) {
                ctx.lockout_recovery_time = properties[i].value;
                continue;
            }
        }
        free(capabilities);
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

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    if (!ctx.clear_lockout && !ctx.setup_parameters) {
        LOG_ERR("Invalid operational input: Neither Setup nor Clear lockout "
            "requested.");
        return tool_rc_option_error;
    }

    if (ctx.setup_parameters && ctx.clear_lockout && ctx.cp_hash_path) {
        LOG_ERR("When calculating pHash, select parameter setup or reset,"
            " not both");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.clear_lockout = true;
        break;
    case 's':
        ctx.setup_parameters = true;
        break;
    case 'p':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'n':
        result = tpm2_util_string_to_uint32(value, &ctx.max_tries);
        if (!result) {
            LOG_ERR("Could not convert max_tries to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.max_tries == 0) {
            return false;
        }

        ctx.is_setup_max_tries = true;
        break;
    case 't':
        result = tpm2_util_string_to_uint32(value, &ctx.recovery_time);
        if (!result) {
            LOG_ERR("Could not convert recovery_time to number, got: \"%s\"",
                    value);
            return false;
        }

        ctx.is_setup_recovery_time = true;
        break;
    case 'l':
        result = tpm2_util_string_to_uint32(value, &ctx.lockout_recovery_time);
        if (!result) {
            LOG_ERR("Could not convert lockout_recovery_time to number, got: "
                "\"%s\"", value);
            return false;
        }
        ctx.is_setup_lockoutrecovery_time = true;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "max-tries",             required_argument, 0, 'n' },
        { "recovery-time",         required_argument, 0, 't' },
        { "lockout-recovery-time", required_argument, 0, 'l' },
        { "auth",                  required_argument, 0, 'p' },
        { "clear-lockout",         no_argument,       0, 'c' },
        { "setup-parameters",      no_argument,       0, 's' },
        { "cphash",                required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("n:t:l:p:cs", ARRAY_LEN(topts), topts, on_option,
        0, 0);

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
    rc = dictionarylockout(ectx);
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
TPM2_TOOL_REGISTER("dictionarylockout", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
