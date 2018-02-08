//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct password password;
struct password {
    TPM2B_AUTH old;
    TPM2B_AUTH new;
};

typedef struct changeauth_ctx changeauth_ctx;
struct changeauth_ctx {
    struct {
        password owner;
        password endorse;
        password lockout;
    } passwords;
};

static changeauth_ctx ctx;

static bool change_auth(TSS2_SYS_CONTEXT *sapi_context,
        struct password *pwd, const char *desc,
        TPMI_RH_HIERARCHY_AUTH auth_handle) {

    TPM2B_AUTH newAuth;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .nonce = TPM2B_EMPTY_INIT,
            .hmac = TPM2B_EMPTY_INIT,
           .sessionAttributes = 0,
    }}};

    memcpy(&newAuth, &pwd->new, sizeof(pwd->new));
    memcpy(&sessionsData.auths[0].hmac, &pwd->old, sizeof(pwd->old));

    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_HierarchyChangeAuth(sapi_context,
            auth_handle, &sessionsData, &newAuth, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_HierarchyChangeAuth, rval);
        return false;
    }

    LOG_INFO("Successfully changed hierarchy for %s", desc);

    return true;
}

static bool change_hierarchy_auth(TSS2_SYS_CONTEXT *sapi_context) {

    // change owner, endorsement and lockout auth.
    return change_auth(sapi_context, &ctx.passwords.owner,
                "Owner", TPM2_RH_OWNER)
        && change_auth(sapi_context, &ctx.passwords.endorse,
                "Endorsement", TPM2_RH_ENDORSEMENT)
        && change_auth(sapi_context, &ctx.passwords.lockout,
                "Lockout", TPM2_RH_LOCKOUT);
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {

    case 'o':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.owner.new);
        if (!result) {
            LOG_ERR("Invalid new owner password, got\"%s\"", value);
            return false;
        }
        break;
    case 'e':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.endorse.new);
        if (!result) {
            LOG_ERR("Invalid new endorse password, got\"%s\"", value);
            return false;
        }
        break;
    case 'l':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.lockout.new);
        if (!result) {
            LOG_ERR("Invalid new lockout password, got\"%s\"", value);
            return false;
        }
        break;
    case 'O':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.owner.old);
        if (!result) {
            LOG_ERR("Invalid current owner password, got\"%s\"", value);
            return false;
        }
        break;
    case 'E':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.endorse.old);
        if (!result) {
            LOG_ERR("Invalid current endorse password, got\"%s\"", value);
            return false;
        }
        break;
    case 'L':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.lockout.old);
        if (!result) {
            LOG_ERR("Invalid current lockout password, got\"%s\"", value);
            return false;
        }
        break;
        /*no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    struct option topts[] = {
        { "owner-passwd",       required_argument, NULL, 'o' },
        { "endorse-passwd",     required_argument, NULL, 'e' },
        { "lockout-passwd",     required_argument, NULL, 'l' },
        { "old-owner-passwd",   required_argument, NULL, 'O' },
        { "old-endorse-passwd", required_argument, NULL, 'E' },
        { "old-ockout-passwd",  required_argument, NULL, 'L' },
    };

    *opts = tpm2_options_new("o:e:l:O:E:L:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    /* true is success, coerce to 0 for program success */
    return change_hierarchy_auth(sapi_context) == false;
}
