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
#include <limits.h>
#include <sapi/tpm20.h>

#include "../lib/tpm2_password_util.h"
#include "tpm2_util.h"
#include "log.h"
#include "files.h"
#include "main.h"
#include "options.h"
#include "tpm2_alg_util.h"

typedef struct tpm_hmac_ctx tpm_hmac_ctx;
struct tpm_hmac_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_DH_OBJECT key_handle;
    TPMI_ALG_HASH algorithm;
    char *hmac_output_file_path;
    TPM2B_MAX_BUFFER data;
    TSS2_SYS_CONTEXT *sapi_context;
    bool is_auth_session;
    TPMI_SH_AUTH_SESSION auth_session_handle;
};

static bool do_hmac_and_output(tpm_hmac_ctx *ctx) {

    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    TPM2B_DIGEST hmac_out = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    session_data_array[0] = &ctx->session_data;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    ctx->session_data.sessionHandle = TPM_RS_PW;

    if(ctx->is_auth_session) {
        ctx->session_data.sessionHandle = ctx->auth_session_handle;
    }

    TPM_RC rval = Tss2_Sys_HMAC(ctx->sapi_context, ctx->key_handle,
            &sessions_data, &ctx->data, ctx->algorithm, &hmac_out,
            &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_HMAC Error. TPM Error:0x%x", rval);
        return -1;
    }

    printf("\nhmac value(hex type): ");
    UINT16 i;
    for (i = 0; i < hmac_out.t.size; i++)
        printf("%02x ", hmac_out.t.buffer[i]);
    printf("\n");

    /* TODO fix serialization */
    return files_save_bytes_to_file(ctx->hmac_output_file_path, (UINT8 *) &hmac_out,
            sizeof(hmac_out));
}

#define ARG_CNT(optional) ((int)(2 * (sizeof(long_options)/sizeof(long_options[0]) - optional - 1)))

static bool init(int argc, char *argv[], tpm_hmac_ctx *ctx) {

    bool result = false;
    bool is_hex_passwd = false;
    char *contextKeyFile = NULL;

    const char *optstring = "k:P:g:I:o:S:c:X";
    static struct option long_options[] = {
        {"keyHandle",   required_argument, NULL, 'k'},
        {"keyContext",  required_argument, NULL, 'c'},
        {"pwdk",        required_argument, NULL, 'P'},
        {"algorithm",   required_argument, NULL, 'g'},
        {"infile",      required_argument, NULL, 'I'},
        {"outfile",     required_argument, NULL, 'o'},
        {"input-session-handle",1,         NULL, 'S'},
        {"passwdInHex", no_argument,       NULL, 'X'},
        {NULL,          no_argument,       NULL, '\0'}
    };

    union {
        struct {
            UINT8 k : 1;
            UINT8 P : 1;
            UINT8 g : 1;
            UINT8 I : 1;
            UINT8 o : 1;
            UINT8 c : 1;
            UINT8 unused : 2;
        };
        UINT8 all;
    } flags = { .all = 0 };

    /*
     * argc should be bound by the maximum and minimum option count.
     * subtract 1 from argc to disregard argv[0]
     */
    if ((argc - 1) < 1 || (argc - 1) > ARG_CNT(0)) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt = -1;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'k':
            result = tpm2_util_string_to_uint32(optarg, &ctx->key_handle);
            if (!result) {
                LOG_ERR("Could not convert key handle to number, got \"%s\"",
                        optarg);
                return false;
            }
            flags.k = 1;
            break;
        case 'P':
            result = tpm2_password_util_copy_password(optarg, "key handle",
                    &ctx->session_data.hmac);
            if (!result) {
                return false;
            }
            flags.P = 1;
            break;
        case 'g':
            ctx->algorithm = tpm2_alg_util_from_optarg(optarg);
            if (ctx->algorithm == TPM_ALG_ERROR) {
                LOG_ERR("Could not convert algorithm to number, got \"%s\"",
                        optarg);
                return false;
            }
            flags.g = 1;
            break;
        case 'I':
            ctx->data.t.size = BUFFER_SIZE(TPM2B_MAX_BUFFER, buffer);
            result = files_load_bytes_from_file(optarg, ctx->data.t.buffer,
                    &ctx->data.t.size);
            if (!result) {
                return false;
            }
            flags.I = 1;
            break;
        case 'o':
            result = files_does_file_exist(optarg);
            if (result) {
                return false;
            }
            ctx->hmac_output_file_path = optarg;
            flags.o = 1;
            break;
        case 'c':
            if (contextKeyFile) {
                LOG_ERR("Multiple specifications of -c");
                return false;
            }
            contextKeyFile = optarg;
            flags.c = 1;
            break;
        case 'X':
            is_hex_passwd = true;
            break;
        case 'S':
            if (!tpm2_util_string_to_uint32(optarg, &ctx->auth_session_handle)) {
                LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
            ctx->is_auth_session = true;
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

    /*
     * Options g, I, o must be specified and k or c must be specified.
     */
    if (!((flags.k || flags.c) && flags.I && flags.o && flags.g)) {
        LOG_ERR("Must specify options g, i, o and k or c");
        return false;
    }

    if (flags.c) {
        result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->key_handle,
                contextKeyFile);
        if (!result) {
            LOG_ERR("Loading tpm context from file \"%s\" failed.",
                    contextKeyFile);
            return false;
        }
    }

    /* convert a hex password if needed */
    return tpm2_password_util_fromhex(&ctx->session_data.hmac, is_hex_passwd,
            "key handle", &ctx->session_data.hmac);
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    tpm_hmac_ctx ctx = {
            .session_data = TPMS_AUTH_COMMAND_EMPTY_INIT,
            .key_handle = 0,
            .sapi_context = sapi_context,
            .is_auth_session = false
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return do_hmac_and_output(&ctx) != true;
}
