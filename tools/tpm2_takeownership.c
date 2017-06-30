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

#include "../lib/tpm2_util.h"
#include "log.h"
#include "options.h"
#include "main.h"
#include "password_util.h"

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
    bool is_hex_passwords;
    TSS2_SYS_CONTEXT *sapi_context;
};

bool clear_hierarchy_auth(takeownership_ctx *ctx) {

    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *) ((void *) &sessionData.sessionAttributes)) = 0;

    bool result = password_tpm2_util_to_auth(&ctx->passwords.lockout.old, ctx->is_hex_passwords, "old lockout", &sessionData.hmac);
    if (!result) {
        return false;
    }

    UINT32 rval = Tss2_Sys_Clear(ctx->sapi_context, TPM_RH_LOCKOUT, &sessionsData, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Clearing Failed! TPM error code: 0x%0x", rval);
        return false;
    }

    return true;
}

#define ARRAY_LEN(x) (sizeof(x)/sizeof(*x))

static bool change_hierarchy_auth(takeownership_ctx *ctx) {

    TPM2B_AUTH newAuth;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *) ((void *) &sessionData.sessionAttributes)) = 0;

    struct {
        TPM2B_AUTH *new_passwd;
        TPM2B_AUTH *old_passwd;
        TPMI_RH_HIERARCHY_AUTH auth_handle;
        char *desc;
    } sources[] = {
            {
                    .new_passwd = &ctx->passwords.owner.new,
                    .old_passwd = &ctx->passwords.owner.old,
                    .auth_handle = TPM_RH_OWNER,
                    .desc = "Owner"
            },
            {
                    .new_passwd = &ctx->passwords.endorse.new,
                    .old_passwd = &ctx->passwords.endorse.old,
                    .auth_handle = TPM_RH_ENDORSEMENT,
                    .desc = "Endorsement"
            },
            {
                    .new_passwd = &ctx->passwords.lockout.new,
                    .old_passwd = &ctx->passwords.lockout.old,
                    .auth_handle = TPM_RH_LOCKOUT,
                    .desc = "Lockout"
            }
    };

    unsigned i;
    for (i = 0; i < ARRAY_LEN(sources); i++) {

        unsigned j;
        for (j = 0; j < 2; j++) {
            TPM2B_AUTH *passwd =
                    j == 0 ? sources[i].new_passwd : sources[i].old_passwd;
            TPM2B_AUTH *auth_dest = j == 0 ? &newAuth : &sessionData.hmac;

            char desc[256];
            snprintf(desc, sizeof(desc), "%s %s",
                    j == 0 ? "new" : "old", sources[i].desc);

            bool result = password_tpm2_util_to_auth(passwd, ctx->is_hex_passwords, desc,
                    auth_dest);
            if (!result) {
                return false;
            }
        }

        UINT32 rval = Tss2_Sys_HierarchyChangeAuth(ctx->sapi_context,
                sources[i].auth_handle, &sessionsData, &newAuth, 0);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Could not change hierarchy for %s. TPM Error:0x%x",
                    sources[i].desc, rval);
            return false;
        }

        LOG_INFO("Successfully changed hierarchy for %s", sources[i].desc);
    }

    return true;
}

static bool init(int argc, char *argv[], char *envp[], takeownership_ctx *ctx,
        bool *clear_auth) {

    struct option sOpts[] = {
            { "ownerPasswd",      required_argument, NULL, 'o' },
            {"endorsePasswd",     required_argument, NULL, 'e' },
            { "lockPasswd",       required_argument, NULL, 'l' },
            { "oldOwnerPasswd",   required_argument, NULL, 'O' },
            { "oldEndorsePasswd", required_argument, NULL, 'E' },
            { "oldLockPasswd",    required_argument, NULL, 'L' },
            { "passwdInHex",      no_argument,       NULL, 'X' },
            { "clear",            no_argument,       NULL, 'c' },
            { NULL,               no_argument,       NULL, '\0' },
    };

    if (argc == 1) {
        execute_man(argv[0], envp);
        return false;
    }

    if (argc > (int) (2 * sizeof(sOpts) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return false;
    }

    *clear_auth = false;

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "o:e:l:O:E:L:Xc", sOpts, NULL))
            != -1) {

        switch (opt) {
        case 'c':
            *clear_auth = true;
            break;

        case 'o':
            result = password_tpm2_util_copy_password(optarg, "new owner password",
                    &ctx->passwords.owner.new);
            if (!result) {
                return false;
            }
            break;
        case 'e':
            result = password_tpm2_util_copy_password(optarg, "new endorse password",
                    &ctx->passwords.endorse.new);
            if (!result) {
                return false;
            }
            break;
        case 'l':
            result = password_tpm2_util_copy_password(optarg, "new lockout password",
                    &ctx->passwords.lockout.new);
            if (!result) {
                return false;
            }
            break;
        case 'O':
            result = password_tpm2_util_copy_password(optarg, "current owner password",
                    &ctx->passwords.owner.old);
            if (!result) {
                return false;
            }
            break;
        case 'E':
            result = password_tpm2_util_copy_password(optarg, "current endorse password",
                    &ctx->passwords.endorse.old);
            if (!result) {
                return false;
            }
            break;
        case 'L':
            result = password_tpm2_util_copy_password(optarg, "current lockout password",
                    &ctx->passwords.lockout.old);
            if (!result) {
                return false;
            }
            break;
        case 'X':
            ctx->is_hex_passwords = true;
            break;
        case '?':
        default:
            showArgMismatch(argv[0]);
            return false;
        }
    }
    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused */
    (void) opts;

    takeownership_ctx ctx = {
            .sapi_context = sapi_context,
            .is_hex_passwords = false
    };

    bool clear_auth = false;
    bool result = init(argc, argv, envp, &ctx, &clear_auth);
    if (!result) {
        return 1;
    }

    int rc = (clear_auth ? clear_hierarchy_auth(&ctx) : change_hierarchy_auth(&ctx));

    /* true is success, coerce to 0 for program success */
    return rc == false;
}
