/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_options.h"

typedef struct dictionarylockout_ctx dictionarylockout_ctx;
struct dictionarylockout_ctx {
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
    char *cp_hash_path;
};

static dictionarylockout_ctx ctx = {
    .auth_hierarchy.ctx_path = "l",
};

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

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "max-tries",             required_argument, NULL, 'n' },
        { "recovery-time",         required_argument, NULL, 't' },
        { "lockout-recovery-time", required_argument, NULL, 'l' },
        { "auth",                  required_argument, NULL, 'p' },
        { "clear-lockout",         no_argument,       NULL, 'c' },
        { "setup-parameters",      no_argument,       NULL, 's' },
        { "cphash",                required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("n:t:l:p:cs", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.clear_lockout && !ctx.setup_parameters) {
        LOG_ERR("Invalid operational input: Neither Setup nor Clear lockout "
                "requested.");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_L);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid authorization");
        return rc;
    }

    /*
     * If calculating cpHash without executing the command, skip reading
     * existing dictionary lockout parameters.
     */
    if (ctx.setup_parameters && !ctx.cp_hash_path) {
        TPMS_CAPABILITY_DATA *capabilities = NULL;
        rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_VAR,
            TPM2_MAX_TPM_PROPERTIES, NULL, &capabilities);
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

    TPM2B_DIGEST cp_hash = { .size = 0 };
    if (ctx.cp_hash_path && ctx.clear_lockout) {
        LOG_WARN("Calculating cpHash. Exiting without resetting dictionary lockout");
        tool_rc rc = tpm2_dictionarylockout_reset(ectx,
        &ctx.auth_hierarchy.object, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }
        goto out;
    }

    if (ctx.cp_hash_path && ctx.setup_parameters) {
        LOG_WARN("Calculating cpHash. Exiting without setting dictionary lockout");
        tool_rc rc = tpm2_dictionarylockout_setup(ectx,
        &ctx.auth_hierarchy.object, ctx.max_tries, ctx.recovery_time,
        ctx.lockout_recovery_time, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }
        goto out;
    }

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * precede parameters setup.
     */
    if (ctx.clear_lockout) {
        return tpm2_dictionarylockout_reset(ectx, &ctx.auth_hierarchy.object,
        NULL);
    }

    if (ctx.setup_parameters) {
        return tpm2_dictionarylockout_setup(ectx, &ctx.auth_hierarchy.object,
        ctx.max_tries, ctx.recovery_time, ctx.lockout_recovery_time, NULL);
    }

out:
    if (ctx.cp_hash_path) {
        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
    }
    return rc;
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
