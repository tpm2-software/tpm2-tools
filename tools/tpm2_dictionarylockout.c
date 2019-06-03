/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct dictionarylockout_ctx dictionarylockout_ctx;
struct dictionarylockout_ctx {
    UINT32 max_tries;
    UINT32 recovery_time;
    UINT32 lockout_recovery_time;
    bool clear_lockout;
    bool setup_parameters;

    struct {
        tpm2_session *session;
        char *auth_str;
    } auth;
};

static dictionarylockout_ctx ctx;

tool_rc dictionary_lockout_reset_and_parameter_setup(ESYS_CONTEXT *ectx) {

    TPM2_RC rval;
    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_LOCKOUT,
                            ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle for lockout hierarchy");
        return tool_rc_general_error;
    }

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * precede parameters setup.
     */
    if (ctx.clear_lockout) {

        LOG_INFO("Resetting dictionary lockout state.");
        rval = Esys_DictionaryAttackLockReset(ectx, ESYS_TR_RH_LOCKOUT,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_DictionaryAttackLockReset, rval);
            return tool_rc_from_tpm(rval);
        }
    }

    if (ctx.setup_parameters) {
        LOG_INFO("Setting up Dictionary Lockout parameters.");
        rval = Esys_DictionaryAttackParameters(ectx, ESYS_TR_RH_LOCKOUT,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                    ctx.max_tries, ctx.recovery_time,
                    ctx.lockout_recovery_time);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_DictionaryAttackParameters, rval);
            return tool_rc_from_tpm(rval);
        }
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
        ctx.auth.auth_str = value;
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
            LOG_ERR("Could not convert lockout_recovery_time to number, got: \"%s\"",
                    value);
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
        { "auth-lockout",          required_argument, NULL, 'p' },
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
        LOG_ERR( "Invalid operational input: Neither Setup nor Clear lockout requested.");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid lockout authorization, got\"%s\"",
            ctx.auth.auth_str);
        return rc;
    }

    return dictionary_lockout_reset_and_parameter_setup(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth.session);
}
