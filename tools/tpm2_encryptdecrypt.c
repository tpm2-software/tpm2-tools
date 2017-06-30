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

#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "../lib/tpm2_util.h"
#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "password_util.h"

typedef struct tpm_encrypt_decrypt_ctx tpm_encrypt_decrypt_ctx;
struct tpm_encrypt_decrypt_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_YES_NO is_decrypt;
    TPMI_DH_OBJECT key_handle;
    TPM2B_MAX_BUFFER data;
    char out_file_path[PATH_MAX];
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool encryptDecrypt(tpm_encrypt_decrypt_ctx *ctx) {

    TPM2B_MAX_BUFFER out_data = TPM2B_TYPE_INIT(TPM2B_MAX_BUFFER, buffer);

    TPM2B_IV iv_out = TPM2B_TYPE_INIT(TPM2B_IV, buffer);

    TSS2_SYS_CMD_AUTHS sessions_data;
    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    session_data_array[0] = &ctx->session_data;
    sessions_data.cmdAuths = &session_data_array[0];
    session_data_out_array[0] = &session_data_out;
    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data_out.rspAuthsCount = 1;

    sessions_data.cmdAuthsCount = 1;
    sessions_data.cmdAuths[0] = &ctx->session_data;

    TPM2B_IV iv_in = {
        .t = {
            .size = MAX_SYM_BLOCK_SIZE,
            .buffer = { 0 }
        },
    };

    TPM_RC rval = Tss2_Sys_EncryptDecrypt(ctx->sapi_context, ctx->key_handle,
            &sessions_data, ctx->is_decrypt, TPM_ALG_NULL, &iv_in, &ctx->data, &out_data,
            &iv_out, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("EncryptDecrypt failed, error code: 0x%x\n", rval);
        return false;
    }

    return files_save_bytes_to_file(ctx->out_file_path, (UINT8 *) out_data.t.buffer,
            out_data.t.size);
}

static bool init(int argc, char *argv[], tpm_encrypt_decrypt_ctx *ctx) {

    bool result = false;
    bool is_hex_passwd = false;

    int opt = -1;
    const char *optstring = "k:P:D:I:o:c:X";
    static struct option long_options[] = {
      {"keyHandle",   required_argument, NULL, 'k'},
      {"pwdk",        required_argument, NULL, 'P'},
      {"decrypt",     required_argument, NULL, 'D'},
      {"inFile",      required_argument, NULL, 'I'},
      {"outFile",     required_argument, NULL, 'o'},
      {"keyContext",  required_argument, NULL, 'c'},
      {"passwdInHex", no_argument,       NULL, 'X'},
      {NULL,          no_argument,       NULL, '\0'}
    };

    struct {
        UINT8 k : 1;
        UINT8 P : 1;
        UINT8 D : 1;
        UINT8 I : 1;
        UINT8 o : 1;
        UINT8 c : 1;
        UINT8 X : 1;
        UINT8 unused : 1;
    } flags = { 0 };

    char *contextKeyFile = NULL;

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        case 'k':
            result = tpm2_util_string_to_uint32(optarg, &ctx->key_handle);
            if (!result) {
                LOG_ERR("Could not convert keyhandle to number, got: \"%s\"",
                        optarg);
                goto out;
            }
            flags.k = 1;
            break;
        case 'P':
            result = password_tpm2_util_copy_password(optarg, "key", &ctx->session_data.hmac);
            if (!result) {
                goto out;
            }
            flags.P = 1;
            break;
        case 'D':
            if (!strcasecmp("YES", optarg)) {
                ctx->is_decrypt = YES;
            } else if (!strcasecmp("NO", optarg)) {
                ctx->is_decrypt = NO;
            } else {
                showArgError(optarg, argv[0]);
                goto out;
            }
            break;
        case 'I':
            ctx->data.t.size = sizeof(ctx->data) - 2;
            result = files_load_bytes_from_file(optarg, ctx->data.t.buffer, &ctx->data.t.size);
            if (!result) {
                goto out;
            }
            flags.I = 1;
            break;
        case 'o':
            result = files_does_file_exist(optarg);
            if (result) {
                goto out;
            }
            snprintf(ctx->out_file_path, sizeof(ctx->out_file_path), "%s",
                    optarg);
            flags.o = 1;
            break;
        case 'c':
            if (contextKeyFile) {
                LOG_ERR("Multiple specifications of -c");
                goto out;
            }
            contextKeyFile = strdup(optarg);
            if (!contextKeyFile) {
                LOG_ERR("OOM");
                goto out;
            }
            flags.c = 1;
            break;
        case 'X':
            is_hex_passwd = true;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            goto out;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            goto out;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            goto out;
        }
    }

    if (!((flags.k || flags.c) && flags.I && flags.o)) {
        LOG_ERR("Invalid arguments");
        goto out;
    }

    if (flags.c) {
        result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->key_handle, contextKeyFile);
        if (!result) {
            goto out;
        }
    }

    result = password_tpm2_util_to_auth(&ctx->session_data.hmac, is_hex_passwd, "key",
            &ctx->session_data.hmac);

out:
    free(contextKeyFile);

    return result;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts and envp are unused, avoid compiler warning */
    (void) opts;
    (void) envp;

    tpm_encrypt_decrypt_ctx ctx = {
        .session_data = { 0 },
        .is_decrypt = NO,
        .data = {{ 0 }},
        .sapi_context = sapi_context
    };

    ctx.session_data.sessionHandle = TPM_RS_PW;

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return false;
    }

    return encryptDecrypt(&ctx) != true;
}
