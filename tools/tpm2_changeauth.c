//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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

#include <tss2/tss2_sys.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct auth auth;
struct auth {
    struct {
        TPMS_AUTH_COMMAND auth;
        tpm2_session *session;
    } old;
    struct {
        TPMS_AUTH_COMMAND auth;
    } new;
};

typedef struct changeauth_ctx changeauth_ctx;
struct changeauth_ctx {
    struct {
        auth owner;
        auth endorse;
        auth lockout;
    } auths;
};

static changeauth_ctx ctx = {
    .auths = {
        .owner = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        },
        .endorse = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        },
        .lockout = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) }
        },
    }
};

static bool change_auth(TSS2_SYS_CONTEXT *sapi_context,
        struct auth *pwd, const char *desc,
        TPMI_RH_HIERARCHY_AUTH auth_handle) {

    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = { pwd->old.auth }
    };

    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_HierarchyChangeAuth(sapi_context,
            auth_handle, &sessionsData, &pwd->new.auth.hmac, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_HierarchyChangeAuth, rval);
        return false;
    }

    LOG_INFO("Successfully changed hierarchy for %s", desc);

    return true;
}

static bool change_hierarchy_auth(TSS2_SYS_CONTEXT *sapi_context) {

    // change owner, endorsement and lockout auth.
    return change_auth(sapi_context, &ctx.auths.owner,
                "Owner", TPM2_RH_OWNER)
        && change_auth(sapi_context, &ctx.auths.endorse,
                "Endorsement", TPM2_RH_ENDORSEMENT)
        && change_auth(sapi_context, &ctx.auths.lockout,
                "Lockout", TPM2_RH_LOCKOUT);
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {

    case 'o':
        result = tpm2_auth_util_from_optarg(value, &ctx.auths.owner.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new owner authorization, got\"%s\"", value);
            return false;
        }
        break;
    case 'e':
        result = tpm2_auth_util_from_optarg(value, &ctx.auths.endorse.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new endorse authorization, got\"%s\"", value);
            return false;
        }
        break;
    case 'l':
        result = tpm2_auth_util_from_optarg(value, &ctx.auths.lockout.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new lockout authorization, got\"%s\"", value);
            return false;
        }
        break;
    case 'O':
        result = tpm2_auth_util_from_optarg(value, &ctx.auths.owner.old.auth,
                &ctx.auths.owner.old.session);
        if (!result) {
            LOG_ERR("Invalid current owner authorization, got\"%s\"", value);
            return false;
        }
        break;
    case 'E':
        result = tpm2_auth_util_from_optarg(value, &ctx.auths.endorse.old.auth,
                &ctx.auths.endorse.old.session);
        if (!result) {
            LOG_ERR("Invalid current endorse authorization, got\"%s\"", value);
            return false;
        }
        break;
    case 'L':
        result = tpm2_auth_util_from_optarg(value, &ctx.auths.lockout.old.auth,
                &ctx.auths.lockout.old.session);
        if (!result) {
            LOG_ERR("Invalid current lockout authorization, got\"%s\"", value);
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
        { "old-auth-owner",     required_argument, NULL, 'O' },
        { "old-auth-endorse",   required_argument, NULL, 'E' },
        { "old-auth-lockout",   required_argument, NULL, 'L' },
    };

    *opts = tpm2_options_new("o:e:l:O:E:L:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);


    bool result = change_hierarchy_auth(sapi_context);

    result &= tpm2_session_save(sapi_context, ctx.auths.endorse.old.session, NULL);
    result &= tpm2_session_save(sapi_context, ctx.auths.owner.old.session, NULL);
    result &= tpm2_session_save(sapi_context, ctx.auths.lockout.old.session, NULL);

    /* true is success, coerce to 0 for program success */
    return result == false;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auths.endorse.old.session);
    tpm2_session_free(&ctx.auths.owner.old.session);
    tpm2_session_free(&ctx.auths.lockout.old.session);
}
