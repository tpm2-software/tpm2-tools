//**********************************************************************;
// Copyright (c) 2015-2018 Intel Corporation
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
#include <string.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_util.h"

typedef struct password password;
struct password {
    TPM2B_AUTH old;
    TPM2B_AUTH new;
};

typedef struct takeownership_ctx takeownership_ctx;
struct takeownership_ctx {
    struct {
        password owner;
        password platform;
        password endorse;
        password lockout;
    } passwords;

    struct {
        UINT8 clear_auth : 1;
        UINT8 unused     : 7;
    };

    struct {
        UINT8 o : 1;
        UINT8 p : 1;
        UINT8 e : 1;
        UINT8 l : 1;
        UINT8 O : 1;
        UINT8 P : 1;
        UINT8 E : 1;
        UINT8 L : 1;
    } flags;
};

static takeownership_ctx ctx;

static bool clear_hierarchy_auth(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = { TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW)}
    };

    memcpy(&sessionsData.auths[0].hmac, &ctx.passwords.lockout.old, sizeof(ctx.passwords.lockout.old));

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Clear(sapi_context, TPM2_RH_LOCKOUT, &sessionsData, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Clearing Failed! TPM error code: 0x%0x", rval);
        return false;
    }

    return true;
}

static bool change_auth(TSS2_SYS_CONTEXT *sapi_context,
        struct password *pwd, const char *desc,
        TPMI_RH_HIERARCHY_AUTH auth_handle) {

    TPM2B_AUTH newAuth;
    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = { TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW)}
    };


    memcpy(&newAuth, &pwd->new, sizeof(pwd->new));
    memcpy(&sessionsData.auths[0].hmac, &pwd->old, sizeof(pwd->old));

    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_HierarchyChangeAuth(sapi_context,
            auth_handle, &sessionsData, &newAuth, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Could not change hierarchy for %s. TPM Error:0x%x",
                desc, rval);
        return false;
    }

    LOG_INFO("Successfully changed hierarchy for %s", desc);

    return true;
}

static bool change_hierarchy_auth(TSS2_SYS_CONTEXT *sapi_context) {

    // change owner, endorsement and lockout auth.
    bool result = true;
    if (ctx.flags.o || ctx.flags.O) {
        result &= change_auth(sapi_context, &ctx.passwords.owner,
                        "Owner", TPM2_RH_OWNER);
    }

    if (ctx.flags.p || ctx.flags.P) {
        result &= change_auth(sapi_context, &ctx.passwords.platform,
                        "Platform", TPM2_RH_PLATFORM);
    }

    if (ctx.flags.e || ctx.flags.E) {
        result &= change_auth(sapi_context, &ctx.passwords.endorse,
                        "Endorsement", TPM2_RH_ENDORSEMENT);
    }

    if (ctx.flags.l || ctx.flags.L) {
        result &= change_auth(sapi_context, &ctx.passwords.lockout,
                        "Lockout", TPM2_RH_LOCKOUT);
    }

    return result;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.clear_auth = true;
        break;

    case 'o':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.owner.new);
        if (!result) {
            LOG_ERR("Invalid new owner password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.o = 1;
        break;
    case 'p':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.platform.new);
        if (!result) {
            LOG_ERR("Invalid new platform password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.p = 1;
        break;
    case 'e':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.endorse.new);
        if (!result) {
            LOG_ERR("Invalid new endorse password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.e = 1;
        break;
    case 'l':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.lockout.new);
        if (!result) {
            LOG_ERR("Invalid new lockout password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.l = 1;
        break;
    case 'O':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.owner.old);
        if (!result) {
            LOG_ERR("Invalid current owner password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.O = 1;
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.platform.old);
        if (!result) {
            LOG_ERR("Invalid current platform password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.P = 1;
        break;
    case 'E':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.endorse.old);
        if (!result) {
            LOG_ERR("Invalid current endorse password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.E = 1;
        break;
    case 'L':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.lockout.old);
        if (!result) {
            LOG_ERR("Invalid current lockout password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.L = 1;
        break;
        /*no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    struct option topts[] = {
        { "owner-passwd",      required_argument, NULL, 'o' },
        { "platform-passwd",   required_argument, NULL, 'p' },
        {"endorse-passwd",     required_argument, NULL, 'e' },
        { "lock-passwd",       required_argument, NULL, 'l' },
        { "oldOwnerPasswd",   required_argument, NULL, 'O' },
        { "oldPlatfromPasswd",required_argument, NULL, 'P' },
        { "oldEndorsePasswd", required_argument, NULL, 'E' },
        { "oldLockPasswd",    required_argument, NULL, 'L' },
        { "clear",            no_argument,       NULL, 'c' },
    };

    *opts = tpm2_options_new("o:p:e:l:O:P:E:L:c", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = (ctx.clear_auth ? clear_hierarchy_auth(sapi_context)
            : change_hierarchy_auth(sapi_context));

    /* true is success, coerce to 0 for program success */
    return result == false;
}
