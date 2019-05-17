/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct clearcontrol_ctx clearcontrol_ctx;
struct clearcontrol_ctx {
    TPMI_YES_NO disable_clear;
    bool set;
    bool clear;
    bool specifyhandle;
    ESYS_TR rh;
    struct {
        char *auth_str;
        tpm2_session *session;
    } auth;
};

static clearcontrol_ctx ctx;

static bool clearcontrol(ESYS_CONTEXT *ectx) {

    LOG_WARN ("Sending TPM2_ClearControl(%s) disableClear command with auth handle %s",
            ctx.disable_clear ? "SET" : "CLEAR",
            ctx.rh == ESYS_TR_RH_PLATFORM ? "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");

    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx, ctx.rh, ctx.auth.session);

    TSS2_RC rval = Esys_ClearControl(ectx, ctx.rh,
                shandle, ESYS_TR_NONE, ESYS_TR_NONE, ctx.disable_clear);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Esys_ClearControl, rval);
        return false;
    }

    LOG_INFO ("Success. TSS2_RC: 0x%x", rval);
    return true;
}

static bool set_clearcontrol_auth_handle(const char *value) {

    if (!strcmp(value, "p")) {
        ctx.rh = ESYS_TR_RH_PLATFORM;
        return true;
    }

    if (!strcmp(value, "l")) {
        ctx.rh = ESYS_TR_RH_LOCKOUT;
        return true;
    }

    LOG_ERR("Unknown or unsupported auth handle string."
        " Specify p(latform)|l(ockout)");
    return false;
}

static bool sanitize_input_arguments(void) {

    if (!ctx.specifyhandle) {
        ctx.rh = ESYS_TR_RH_LOCKOUT;
    }

    if (!ctx.set && !ctx.clear) {
        LOG_ERR("Specify operation (set|clear)");
        return false;
    }

    if (ctx.clear && ctx.rh == ESYS_TR_RH_LOCKOUT) {
        LOG_ERR("Only platform hierarchy handle can be specified"
            " for this operation");
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;
    switch (key) {
    case 's':
        ctx.disable_clear = 1;
        ctx.set = true;
        break;
    case 'c':
        ctx.disable_clear = 0;
        ctx.clear = true;
        break;
    case 'a':
        ctx.specifyhandle = true;
        result = set_clearcontrol_auth_handle(value);
        if (!result) {
            return false;
        }
        break;
    case 'p':
        ctx.auth.auth_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "set",            no_argument,       NULL, 's' },
        { "clear",          no_argument,       NULL, 'c' },
        { "auth-handle",    required_argument, NULL, 'a' },
        { "auth",           required_argument, NULL, 'p' },
    };

    *opts = tpm2_options_new("sca:p:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool res = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, true);
    if (!res) {
        LOG_ERR("Invalid authorization, got\"%s\"",
            ctx.auth.auth_str);
        return 1;
    }

    res = sanitize_input_arguments();
    if (!res) {
        return 1;
    }

    return clearcontrol(ectx) != true;
}
