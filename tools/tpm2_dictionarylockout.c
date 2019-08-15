/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

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
        break;
    case 't':
        result = tpm2_util_string_to_uint32(value, &ctx.recovery_time);
        if (!result) {
            LOG_ERR("Could not convert recovery_time to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 'l':
        result = tpm2_util_string_to_uint32(value, &ctx.lockout_recovery_time);
        if (!result) {
            LOG_ERR("Could not convert lockout_recovery_time to number, got: "
                "\"%s\"", value);
            return false;
        }
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

    return tpm2_dictionarylockout(ectx, &ctx.auth_hierarchy.object,
            ctx.clear_lockout, ctx.setup_parameters, ctx.max_tries,
            ctx.recovery_time, ctx.lockout_recovery_time);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
