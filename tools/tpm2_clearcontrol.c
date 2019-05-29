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
    ESYS_TR rh;
    struct {
        char *auth_str;
        tpm2_session *session;
    } auth;
};

static clearcontrol_ctx ctx = {
    .rh = ESYS_TR_RH_PLATFORM,
    .disable_clear = 0,
};

static bool clearcontrol(ESYS_CONTEXT *ectx) {

    LOG_INFO ("Sending TPM2_ClearControl(%s) disableClear command with auth handle %s",
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

    if (!strcmp(value, "p") || !strcmp(value, "platform")) {
        ctx.rh = ESYS_TR_RH_PLATFORM;
        return true;
    }

    if (!strcmp(value, "l") || !strcmp(value, "lockout")) {
        ctx.rh = ESYS_TR_RH_LOCKOUT;
        return true;
    }

    LOG_ERR("Unknown or unsupported auth handle string."
        " Specify -a followed by p(latform)|l(ockout)");
    return false;
}

bool on_arg (int argc, char **argv) {

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

    if (value!=0 && value!=1) {
        LOG_ERR("Please use 0|1|s|c as the argument to specify operation");
        return false;
    }
    ctx.disable_clear = value;

    return true;
}

static bool on_option(char key, char *value) {

    bool result;
    switch (key) {
    case 'a':
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
        { "auth-handle",    required_argument, NULL, 'a' },
        { "auth",           required_argument, NULL, 'p' },
    };

    *opts = tpm2_options_new("a:p:", ARRAY_LEN(topts), topts, on_option,
        on_arg, 0);

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

    if (!ctx.disable_clear && ctx.rh == ESYS_TR_RH_LOCKOUT) {
        LOG_ERR("Only platform hierarchy handle can be specified"
            " for CLEAR operation on disableClear");
        return 1;
    }

    return clearcontrol(ectx) != true;
}
