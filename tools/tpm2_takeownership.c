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

#include <stdarg.h>
#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "options.h"
#include "main.h"
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
        password endorse;
        password lockout;
    } passwords;
    TSS2_SYS_CONTEXT *sapi_context;
};

bool clear_hierarchy_auth(takeownership_ctx *ctx) {

    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    };
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;

    memcpy(&sessionData.hmac, &ctx->passwords.lockout.old, sizeof(ctx->passwords.lockout.old));

    UINT32 rval = Tss2_Sys_Clear(ctx->sapi_context, TPM_RH_LOCKOUT, &sessionsData, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Clearing Failed! TPM error code: 0x%0x", rval);
        return false;
    }

    return true;
}

static bool change_auth(TSS2_SYS_CONTEXT *sapi_context,
        struct password *pwd, const char *desc,
        TPMI_RH_HIERARCHY_AUTH auth_handle) {

    TPM2B_AUTH newAuth;
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    };
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;

    memcpy(&newAuth, &pwd->new, sizeof(pwd->new));
    memcpy(&sessionData.hmac, &pwd->old, sizeof(pwd->old));

    UINT32 rval = Tss2_Sys_HierarchyChangeAuth(sapi_context,
            auth_handle, &sessionsData, &newAuth, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Could not change hierarchy for %s. TPM Error:0x%x",
                desc, rval);
        return false;
    }

    LOG_INFO("Successfully changed hierarchy for %s", desc);

    return true;
}

static bool change_hierarchy_auth(takeownership_ctx *ctx) {

    // change owner, endorsement and lockout auth.
    return change_auth(ctx->sapi_context, &ctx->passwords.owner,
                "Owner", TPM_RH_OWNER)
        && change_auth(ctx->sapi_context, &ctx->passwords.endorse,
                "Endorsement", TPM_RH_ENDORSEMENT)
        && change_auth(ctx->sapi_context, &ctx->passwords.lockout,
                "Lockout", TPM_RH_LOCKOUT);
}

static bool init(int argc, char *argv[], takeownership_ctx *ctx,
        bool *clear_auth) {

    struct option sOpts[] = {
            { "ownerPasswd",      required_argument, NULL, 'o' },
            {"endorsePasswd",     required_argument, NULL, 'e' },
            { "lockPasswd",       required_argument, NULL, 'l' },
            { "oldOwnerPasswd",   required_argument, NULL, 'O' },
            { "oldEndorsePasswd", required_argument, NULL, 'E' },
            { "oldLockPasswd",    required_argument, NULL, 'L' },
            { "clear",            no_argument,       NULL, 'c' },
            { NULL,               no_argument,       NULL, '\0' },
    };

    if (argc == 1) {
        LOG_ERR("Expected arguments, got none.");
        return false;
    }

    if (argc > (int) (2 * sizeof(sOpts) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return false;
    }

    *clear_auth = false;

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "o:e:l:O:E:L:c", sOpts, NULL))
            != -1) {

        switch (opt) {
        case 'c':
            *clear_auth = true;
            break;

        case 'o':
            result = tpm2_password_util_from_optarg(optarg, &ctx->passwords.owner.new);
            if (!result) {
                LOG_ERR("Invalid new owner password, got\"%s\"", optarg);
                return false;
            }
            break;
        case 'e':
            result = tpm2_password_util_from_optarg(optarg, &ctx->passwords.endorse.new);
            if (!result) {
                LOG_ERR("Invalid new endorse password, got\"%s\"", optarg);
                return false;
            }
            break;
        case 'l':
            result = tpm2_password_util_from_optarg(optarg, &ctx->passwords.lockout.new);
            if (!result) {
                LOG_ERR("Invalid new lockout password, got\"%s\"", optarg);
                return false;
            }
            break;
        case 'O':
            result = tpm2_password_util_from_optarg(optarg, &ctx->passwords.owner.old);
            if (!result) {
                LOG_ERR("Invalid current owner password, got\"%s\"", optarg);
                return false;
            }
            break;
        case 'E':
            result = tpm2_password_util_from_optarg(optarg, &ctx->passwords.endorse.old);
            if (!result) {
                LOG_ERR("Invalid current endorse password, got\"%s\"", optarg);
                return false;
            }
            break;
        case 'L':
            result = tpm2_password_util_from_optarg(optarg, &ctx->passwords.lockout.old);
            if (!result) {
                LOG_ERR("Invalid current lockout password, got\"%s\"", optarg);
                return false;
            }
            break;
        case '?':
        default:
            showArgMismatch(argv[0]);
            return false;
        }
    }
    return true;
}

int execute_tool(int argc, char *argv[],  common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused */
    UNUSED(opts);

    takeownership_ctx ctx = {
            .sapi_context = sapi_context,
    };

    bool clear_auth = false;
    bool result = init(argc, argv, &ctx, &clear_auth);
    if (!result) {
        return 1;
    }

    int rc = (clear_auth ? clear_hierarchy_auth(&ctx) : change_hierarchy_auth(&ctx));

    /* true is success, coerce to 0 for program success */
    return rc == false;
}
