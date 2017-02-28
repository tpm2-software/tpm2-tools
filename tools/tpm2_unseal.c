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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "password_util.h"
#include "string-bytes.h"

typedef struct tpm_unseal_ctx tpm_unseal_ctx;
struct tpm_unseal_ctx {
    TPMS_AUTH_COMMAND sessionData;
    TPMI_DH_OBJECT itemHandle;
    char outFilePath[PATH_MAX];
    TSS2_SYS_CONTEXT *sapi_context;
};

bool unseal_and_save(tpm_unseal_ctx *ctx) {

    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    TPM2B_SENSITIVE_DATA outData = {
            { sizeof(TPM2B_SENSITIVE_DATA) - 2, }
    };

    session_data_array[0] = &ctx->sessionData;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    TPM_RC rval = Tss2_Sys_Unseal(ctx->sapi_context, ctx->itemHandle,
            &sessions_data, &outData, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Sys_Unseal failed. Error Code: 0x%x", rval);
        return false;
    }

    return saveDataToFile(ctx->outFilePath, (UINT8 *) &outData, sizeof(outData))
            == 0;
}

static bool init(int argc, char *argv[], tpm_unseal_ctx *ctx) {

    static const char *optstring = "H:P:o:c:X";
    static const struct option long_options[] = {
      {"item",1,NULL,'H'},
      {"pwdi",1,NULL,'P'},
      {"outfile",1,NULL,'o'},
      {"itemContext",1,NULL,'c'},
      {"passwdInHex",0,NULL,'X'},
      {0,0,0,0}
    };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    struct {
        UINT8 H : 1;
        UINT8 o : 1;
        UINT8 c : 1;
        UINT8 P : 1;
    } flags = { 0 };

    int opt;
    bool hexPasswd = false;
    char contextItemFile[PATH_MAX];
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        case 'H': {
            bool result = string_bytes_get_uint32(optarg, &ctx->itemHandle);
            if (!result) {
                LOG_ERR("Could not cobvert item handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
            flags.H = 1;
        }
            break;
        case 'P': {
            bool result = password_util_copy_password(optarg, "key",
                    &ctx->sessionData.hmac);
            if (!result) {
                return false;
            }
            flags.P = 1;
        }
            break;
        case 'o': {
            bool result = files_does_file_exist(optarg);
            if (result) {
                return false;
            }
            snprintf(ctx->outFilePath, sizeof(ctx->outFilePath), "%s", optarg);
            flags.o = 1;
        }
            break;
        case 'c':
            snprintf(contextItemFile, sizeof(contextItemFile), "%s", optarg);
            flags.c = 1;
            break;
        case 'X':
            hexPasswd = true;
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

    if (!((flags.H || flags.c) && flags.o)) {
        LOG_ERR("Expected options (H or c) and o");
        return false;
    }

    if (flags.P) {
        bool result = password_util_to_auth(&ctx->sessionData.hmac, hexPasswd,
                "key", &ctx->sessionData.hmac);
        if (!result) {
            return false;
        }
    }

    if (flags.c) {
        int rc = loadTpmContextFromFile(ctx->sapi_context, &ctx->itemHandle,
                contextItemFile);
        if (rc) {
            return false;
        }
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts and envp are unused, avoid compiler warning */
    (void)opts;
    (void) envp;

    tpm_unseal_ctx ctx = {
            .sessionData = { 0 },
            .sapi_context = sapi_context
    };

    ctx.sessionData.sessionHandle = TPM_RS_PW;

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return unseal_and_save(&ctx) != true;
}
