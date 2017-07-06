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

#include "../lib/tpm2_util.h"
#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "password_util.h"

typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    TPMI_DH_OBJECT key_handle;
    TPMS_AUTH_COMMAND session_data;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char output_file_path[PATH_MAX];
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool rsa_decrypt_and_save(tpm_rsadecrypt_ctx *ctx) {

    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA message = TPM2B_TYPE_INIT(TPM2B_PUBLIC_KEY_RSA, buffer);

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

    inScheme.scheme = TPM_ALG_RSAES;
    label.t.size = 0;

    TPM_RC rval = Tss2_Sys_RSA_Decrypt(ctx->sapi_context, ctx->key_handle,
            &sessions_data, &ctx->cipher_text, &inScheme, &label, &message,
            &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("rsaDecrypt failed, error code: 0x%x", rval);
        return false;
    }

    return files_save_bytes_to_file(ctx->output_file_path, message.t.buffer,
            message.t.size);
}

static bool init(int argc, char *argv[], tpm_rsadecrypt_ctx *ctx) {

    const char *optstring = "k:P:I:o:c:X";
    static struct option long_options[] = {
      { "keyHandle",   required_argument, NULL, 'k'},
      { "pwdk",        required_argument, NULL, 'P'},
      { "inFile",      required_argument, NULL, 'I'},
      { "outFile",     required_argument, NULL, 'o'},
      { "keyContext",  required_argument, NULL, 'c'},
      { "passwdInHex", no_argument,       NULL, 'X'},
      { NULL,          no_argument,       NULL, '\0'}
    };

    struct {
        UINT8 k : 1;
        UINT8 P : 1;
        UINT8 I : 1;
        UINT8 c : 1;
        UINT8 o : 1;
        UINT8 unused : 3;
    } flags = { 0 };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    bool is_hex_passwd = false;
    char context_key_file[PATH_MAX];

    optind = 0;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'k': {
            bool result = tpm2_util_string_to_uint32(optarg, &ctx->key_handle);
            if (!result) {
                LOG_ERR("Could not convert key handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
            flags.k = 1;
        }
            break;
        case 'P': {
            bool result = password_tpm2_util_copy_password(optarg, "key",
                    &ctx->session_data.hmac);
            if (!result) {
                return false;
            }
            flags.P = 1;
        }
            break;
        case 'I': {
            ctx->cipher_text.t.size = sizeof(ctx->cipher_text) - 2;
            bool result = files_load_bytes_from_file(optarg, ctx->cipher_text.t.buffer,
                    &ctx->cipher_text.t.size);
            if (!result) {
                return false;
            }
            flags.I = 1;
        }
            break;
        case 'o': {
            bool result = files_does_file_exist(optarg);
            if (result) {
                return false;
            }
            snprintf(ctx->output_file_path, sizeof(ctx->output_file_path), "%s",
                    optarg);
            flags.o = 1;
        }
            break;
        case 'c':
            snprintf(context_key_file, sizeof(context_key_file), "%s", optarg);
            flags.c = 1;
            break;
        case 'X':
            is_hex_passwd = true;
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

    if (!((flags.k || flags.c) && flags.I && flags.o)) {
        LOG_ERR("Expected arguments I and o and (k or c)");
        return false;
    }

    if (flags.c) {
        bool result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->key_handle, context_key_file);
        if (!result) {
            return false;
        }
    }

   return password_tpm2_util_to_auth(&ctx->session_data.hmac, is_hex_passwd,
            "key", &ctx->session_data.hmac);
}

ENTRY_POINT(rsadecrypt) {

    /* opts and envp are unused, avoid compiler warning */
    (void)opts;
    (void) envp;

    tpm_rsadecrypt_ctx ctx = {
            .key_handle = 0,
            .cipher_text = {{ 0 }},
            .output_file_path = { 0 },
            .session_data = { 0 },
            .sapi_context = sapi_context
    };

    ctx.session_data.sessionHandle = TPM_RS_PW;

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return rsa_decrypt_and_save(&ctx) != true;
}
