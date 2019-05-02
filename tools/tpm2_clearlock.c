/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017, Emmanuel Deloget <logout@free.fr>
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 */
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct clearlock_ctx clearlock_ctx;
struct clearlock_ctx {
    bool clear;
    bool platform;
    TPMS_AUTH_COMMAND session_data;
    struct {
        UINT8 L : 1;
        UINT8 unused : 7;
    } flags;
    char *lockout_auth_str;
};

static clearlock_ctx ctx = {
    .clear = false,
    .platform = false,
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    .flags = { 0 },
};

static bool clearlock(ESYS_CONTEXT *ectx) {

    ESYS_TR rh = ctx.platform ? ESYS_TR_RH_PLATFORM : ESYS_TR_RH_LOCKOUT;
    TPMI_YES_NO disable = ctx.clear ? 0 : 1;

    LOG_INFO ("Sending TPM2_ClearControl(%s) command on %s",
            ctx.clear ? "CLEAR" : "SET",
            ctx.platform ? "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");

    TSS2_RC rval = Esys_TR_SetAuth(ectx, rh, &ctx.session_data.hmac);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_SetAuth, rval);
        return false;
    }
    
    rval = Esys_ClearControl(ectx, rh,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, disable);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Esys_ClearControl, rval);
        return false;
    }

    LOG_INFO ("Success. TSS2_RC: 0x%x", rval);
    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.clear = true;
        break;
    case 'p':
        ctx.platform = true;
        break;
    case 'L':
        ctx.flags.L = 1;
        ctx.lockout_auth_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "clear",          no_argument,       NULL, 'c' },
        { "auth-lockout",   required_argument, NULL, 'L' },
        { "platform",       no_argument,       NULL, 'p' },
    };

    *opts = tpm2_options_new("cL:p", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.flags.L) {
        bool res = tpm2_auth_util_from_optarg(ectx, ctx.lockout_auth_str,
                &ctx.session_data, NULL);
        if (!res) {
            LOG_ERR("Invalid lockout authorization, got\"%s\"",
                ctx.lockout_auth_str);
            return 1;
        }
    }

    return clearlock(ectx) != true;
}
