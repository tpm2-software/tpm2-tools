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
#include "tpm2_util.h"

typedef struct tpm_rsaencrypt_ctx tpm_rsaencrypt_ctx;
struct tpm_rsaencrypt_ctx {
    TPMI_DH_OBJECT key_handle;
    TPM2B_PUBLIC_KEY_RSA message;
    char *output_file_path;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool rsa_encrypt_and_save(tpm_rsaencrypt_ctx *ctx) {

    // Inputs
    TPMT_RSA_DECRYPT scheme;
    TPM2B_DATA label;
    // Outputs
    TPM2B_PUBLIC_KEY_RSA out_data = TPM2B_TYPE_INIT(TPM2B_PUBLIC_KEY_RSA, buffer);

    TPMS_AUTH_RESPONSE out_session_data;
    TSS2_SYS_RSP_AUTHS out_sessions_data;
    TPMS_AUTH_RESPONSE *out_session_data_array[1];

    out_session_data_array[0] = &out_session_data;
    out_sessions_data.rspAuths = &out_session_data_array[0];
    out_sessions_data.rspAuthsCount = 1;

    scheme.scheme = TPM_ALG_RSAES;
    label.t.size = 0;

    TPM_RC rval = Tss2_Sys_RSA_Encrypt(ctx->sapi_context, ctx->key_handle, NULL,
            &ctx->message, &scheme, &label, &out_data, &out_sessions_data);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("RSA_Encrypt failed, error code: 0x%x", rval);
        return false;
    }

    return files_save_bytes_to_file(ctx->output_file_path, out_data.t.buffer,
            out_data.t.size);
}

static bool init(int argc, char *argv[], tpm_rsaencrypt_ctx *ctx) {

    const char *optstring = "k:I:o:c:";
    static struct option long_options[] = {
      {"keyHandle",  required_argument, NULL, 'k'},
      {"inFile",     required_argument, NULL, 'I'},
      {"outFile",    required_argument, NULL, 'o'},
      {"keyContext", required_argument, NULL, 'c'},
      { NULL,        no_argument,       NULL, '\0'}
    };

    if(argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    union {
        struct {
            UINT8 k : 1;
            UINT8 I : 1;
            UINT8 o : 1;
            UINT8 c : 1;
            UINT8 unused : 4;
        };
        UINT8 all;
    } flags = { .all = 0 };

    int opt;
    char *context_key_file = NULL;
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
        case 'I': {
            ctx->message.t.size = sizeof(ctx->message) - 2;
            bool result = files_load_bytes_from_file(optarg, ctx->message.t.buffer,
                    &ctx->message.t.size);
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
            ctx->output_file_path = optarg;
            flags.o = 1;
        }
            break;
        case 'c':
            context_key_file = optarg;
            flags.c = 1;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??", opt);
            return false;
        }
    };

    if (!((flags.k || flags.c) && flags.I && flags.o)) {
        LOG_ERR("Expected options I and o and (k or c)");
        return false;
    }

    if (flags.c) {
        bool result = files_load_tpm_context_from_file(ctx->sapi_context, &ctx->key_handle,
                context_key_file);
        if (!result) {
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

    tpm_rsaencrypt_ctx ctx = {
            .key_handle = 0,
            .message = TPM2B_EMPTY_INIT,
            .output_file_path = NULL,
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return rsa_encrypt_and_save(&ctx) != true;
}
