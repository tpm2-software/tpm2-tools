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

#include "tpm2_password_util.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"

typedef struct tpm_nvrelease_ctx tpm_nvrelease_ctx;
struct tpm_nvrelease_ctx {
    UINT32 nv_index;
    UINT32 auth_handle;
    TPMS_AUTH_COMMAND session_data;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool nv_space_release(tpm_nvrelease_ctx *ctx) {

    TSS2_SYS_CMD_AUTHS sessions_data;
    TPMS_AUTH_COMMAND *session_data_array[1];

    session_data_array[0] = &ctx->session_data;
    sessions_data.cmdAuths = &session_data_array[0];
    sessions_data.cmdAuthsCount = 1;

    TPM_RC rval = Tss2_Sys_NV_UndefineSpace(ctx->sapi_context, ctx->auth_handle,
            ctx->nv_index, &sessions_data, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed to release NV area at index 0x%x (%d).Error:0x%x",
                ctx->nv_index, ctx->nv_index, rval);
        return false;
    }

    LOG_INFO("Success to release NV area at index 0x%x (%d).\n", ctx->nv_index,
            ctx->nv_index);

    return true;
}

static bool init(int argc, char* argv[], tpm_nvrelease_ctx *ctx) {

    struct option long_options[] = {
        { "index"       , required_argument, NULL, 'x' },
        { "authHandle"  , required_argument, NULL, 'a' },
        { "handlePasswd", required_argument, NULL, 'P' },
        { "input-session-handle",1,          NULL, 'S' },
        { NULL          , no_argument,       NULL,  0  },
    };

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "x:a:s:o:P:S:", long_options, NULL))
            != -1) {
        switch (opt) {
        case 'x':
            result = tpm2_util_string_to_uint32(optarg, &ctx->nv_index);
            if (!result) {
                LOG_ERR("Could not convert NV index to number, got: \"%s\"",
                        optarg);
                return false;
            }

            if (ctx->nv_index == 0) {
                LOG_ERR("NV Index cannot be 0");
                return false;
            }

            break;
        case 'a':
            result = tpm2_util_string_to_uint32(optarg, &ctx->auth_handle);
            if (!result) {
                LOG_ERR("Could not convert auth handle to number, got: \"%s\"",
                        optarg);
                return false;
            }

            if (ctx->auth_handle == 0) {
                LOG_ERR("Auth handle cannot be 0");
                return false;
            }
            break;
        case 'S':
             if (!tpm2_util_string_to_uint32(optarg, &ctx->session_data.sessionHandle)) {
                 LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                         optarg);
                 return false;
             }
             break;
        case 'P':
            result = tpm2_password_util_from_optarg(optarg, &ctx->session_data.hmac);
            if (!result) {
                LOG_ERR("Invalid handle password, got\"%s\"", optarg);
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

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    tpm_nvrelease_ctx ctx = {
            .auth_handle = 0,
            .nv_index = 0,
            .session_data = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW),
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return nv_space_release(&ctx) != true;
}
