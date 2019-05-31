/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct clear_ctx clear_ctx;
struct clear_ctx {
    bool platform;
    struct {
        char *auth_str;
        tpm2_session *session;
    } auth;
};

static clear_ctx ctx;

static tool_rc clear(ESYS_CONTEXT *ectx) {

    ESYS_TR rh = ESYS_TR_RH_LOCKOUT;

    LOG_INFO ("Sending TPM2_Clear command with %s",
            ctx.platform ? "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");
    if (ctx.platform)
        rh = ESYS_TR_RH_PLATFORM;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, rh,
                            ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle for hierarchy");
        return false;
    }

    TSS2_RC rval = Esys_Clear(ectx, rh,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Esys_Clear, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'p':
        ctx.platform = true;
        break;
    case 'L':
        ctx.auth.auth_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "platform",     no_argument,       NULL, 'p' },
        { "auth-lockout", required_argument, NULL, 'L' },
    };

    *opts = tpm2_options_new("pL:", ARRAY_LEN(topts), topts, on_option, NULL,
                             0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    bool result = false;

    result = tpm2_auth_util_from_optarg(NULL, ctx.auth.auth_str,
            &ctx.auth.session, true);
    if (!result) {
        LOG_ERR("Invalid lockout authorization, got\"%s\"", ctx.auth.auth_str);
        return tool_rc_general_error;
    }

    return clear(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth.session);
}
