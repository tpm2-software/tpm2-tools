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
#include <stdio.h>
#include <string.h>

#include <getopt.h>

#include <sapi/tpm20.h>

#include "../lib/tpm2_util.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "password_util.h"

typedef struct dictionarylockout_ctx dictionarylockout_ctx;
struct dictionarylockout_ctx {
    UINT32 max_tries;
    UINT32 recovery_time;
    UINT32 lockout_recovery_time;
    TPM2B_AUTH lockout_passwd;
    bool clear_lockout;
    bool setup_parameters;
    bool use_passwd;
    TSS2_SYS_CONTEXT *sapi_context;
};

bool dictionary_lockout_reset_and_parameter_setup(dictionarylockout_ctx *ctx) {

    //Command Auths
    TPMS_AUTH_COMMAND sessionData = { .sessionHandle = TPM_RS_PW,
            .nonce.t.size = 0, .hmac.t.size = 0, .sessionAttributes.val = 0 };
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;

    TSS2_SYS_CMD_AUTHS sessionsData = { .cmdAuths = &sessionDataArray[0],
            .cmdAuthsCount = 1 };
    if (ctx->use_passwd) {
        bool result = password_tpm2_util_to_auth(&ctx->lockout_passwd, false,
                "Lockout Password", &sessionData.hmac);
        if (!result) {
            return false;
        }
    }

    //Response Auths
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1], sessionDataOut;
    sessionDataOutArray[0] = &sessionDataOut;

    TSS2_SYS_RSP_AUTHS sessionsDataOut = { .rspAuths = &sessionDataOutArray[0],
            .rspAuthsCount = 1 };

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * preceed parameters setup.
     */
    if (ctx->clear_lockout) {

        LOG_INFO("Resetting dictionary lockout state.\n");
        UINT32 rval = Tss2_Sys_DictionaryAttackLockReset(ctx->sapi_context,
                TPM_RH_LOCKOUT, &sessionsData, &sessionsDataOut);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("0x%X Error clearing dictionary lockout.\n", rval);
            return false;
        }
    }

    if (ctx->setup_parameters) {
        LOG_INFO("Setting up Dictionary Lockout parameters.\n");
        UINT32 rval = Tss2_Sys_DictionaryAttackParameters(ctx->sapi_context,
                TPM_RH_LOCKOUT, &sessionsData, ctx->max_tries,
                ctx->recovery_time, ctx->lockout_recovery_time,
                &sessionsDataOut);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR(
                    "0x%X Failed setting up dictionary_attack_lockout_reset params\n",
                    rval);
            return false;
        }
    }

    return true;
}

static bool init(int argc, char *argv[], dictionarylockout_ctx *ctx) {

    struct option long_options[] = {
        { "max-tries", required_argument, NULL, 'n' }, 
        { "recovery-time", required_argument, NULL, 't' }, 
        { "lockout-recovery-time", required_argument, NULL, 'l' }, 
        { "lockout-passwd", required_argument, NULL, 'P' }, 
        { "clear-lockout", no_argument, NULL, 'c' }, 
        { "setup-parameters", no_argument, NULL, 's' }, 
        { NULL, no_argument, NULL, 0 }, 
    };

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "n:t:l:P:cs", long_options, NULL))
            != -1) {
        switch (opt) {
        case 'c':
            ctx->clear_lockout = true;
            break;
        case 's':
            ctx->setup_parameters = true;
            break;
        case 'P':
            result = password_tpm2_util_copy_password(optarg, "Lockout Password",
                    &ctx->lockout_passwd);
            if (!result) {
                return false;
            }
            ctx->use_passwd = true;
            break;
        case 'n':
            result = tpm2_util_string_to_uint32(optarg, &ctx->max_tries);
            if (!result) {
                LOG_ERR("Could not convert max_tries to number, got: \"%s\"",
                        optarg);
                return false;
            }
            if (ctx->max_tries == 0) {
                LOG_ERR("max_tries cannot be 0");
                return false;
            }
            break;
        case 't':
            result = tpm2_util_string_to_uint32(optarg, &ctx->recovery_time);
            if (!result) {
                LOG_ERR(
                        "Could not convert recovery_time to number, got: \"%s\"",
                        optarg);
                return false;
            }
            break;
        case 'l':
            result = tpm2_util_string_to_uint32(optarg,
                    &ctx->lockout_recovery_time);
            if (!result) {
                LOG_ERR(
                        "Could not convert lockout_recovery_time to number, got: \"%s\"",
                        optarg);
                return false;
            }
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            return false;
        }
    }

    if (!ctx->clear_lockout && !ctx->setup_parameters) {
        LOG_ERR( "Invalid operational input: Neither Setup nor Clear lockout requested.\n");
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void) opts;
    (void) envp;

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return -1;
    }

    dictionarylockout_ctx ctx = { 
        .max_tries = 0, 
        .recovery_time = 0,
        .lockout_recovery_time = 0, 
        .clear_lockout = false,
        .setup_parameters = false, 
        .use_passwd = true, 
        .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    result = dictionary_lockout_reset_and_parameter_setup(&ctx);
    if (!result) {
        return 1;
    }

    return 0;
}
