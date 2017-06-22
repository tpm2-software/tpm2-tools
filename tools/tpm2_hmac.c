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

#include "log.h"
#include "files.h"
#include "main.h"
#include "options.h"
#include "password_util.h"
#include "string-bytes.h"

typedef struct tpm_hmac_ctx tpm_hmac_ctx;
struct tpm_hmac_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_DH_OBJECT key_handle;
    TPMI_ALG_HASH algorithm;
    char hmac_output_file_path[PATH_MAX];
    TPM2B_MAX_BUFFER data;
    TSS2_SYS_CONTEXT *sapi_context;
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

    const char *optstring = "k:P:g:I:o:c:X";
    static struct option long_options[] = {
        {"keyHandle",   required_argument, NULL, 'k'},
        {"keyContext",  required_argument, NULL, 'c'},
        {"pwdk",        required_argument, NULL, 'P'},
        {"algorithm",        required_argument, NULL, 'g'},
        {"infile",      required_argument, NULL, 'I'},
        {"outfile",     required_argument, NULL, 'o'},
        {"passwdInHex", no_argument,       NULL, 'X'},
        {NULL,          no_argument,       NULL, '\0'}
    };

    struct {
        UINT8 k : 1;
        UINT8 P : 1;
        UINT8 g : 1;
        UINT8 I : 1;
        UINT8 o : 1;
        UINT8 c : 1;
        UINT8 unused : 2;
    } flags = { 0 };

    /*
     * argc should be bound by the maximum and minimum option count.
     * subtract 1 from argc to disregard argv[0]
     */
    if ((argc - 1) < 1 || (argc - 1) > ARG_CNT(0)) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt = -1;

    optind = 0;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'k':
            result = string_bytes_get_uint32(optarg, &ctx->key_handle);
            if (!result) {
                LOG_ERR("Could not convert key handle to number, got \"%s\"",
                        optarg);
                goto out;
            }
            flags.k = 1;
            break;
        case 'P':
            result = password_util_copy_password(optarg, "key handle",
                    &ctx->session_data.hmac);
            if (!result) {
                goto out;
            }
            flags.P = 1;
            break;
        case 'g':
            result = string_bytes_get_uint16(optarg, &ctx->algorithm);
            if (!result) {
                LOG_ERR("Could not convert algorithm to number, got \"%s\"",
                        optarg);
                goto out;
            }
            flags.g = 1;
            break;
        case 'I':
            ctx->data.t.size = sizeof(ctx->data) - 2;
            result = files_load_bytes_from_file(optarg, ctx->data.t.buffer,
                    &ctx->data.t.size);
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
            snprintf(ctx->hmac_output_file_path,
                    sizeof(ctx->hmac_output_file_path), "%s", optarg);
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

    /*
     * Options g, i, o must be specified and k or c must be specified.
     */
    if (!((flags.k || flags.c) && flags.I && flags.o && flags.g)) {
        LOG_ERR("Must specify options g, i, o and k or c");
        goto out;
    }

    if (flags.c) {
        result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->key_handle,
                contextKeyFile);
        if (!result) {
            LOG_ERR("Loading tpm context from file \"%s\" failed.",
                    contextKeyFile);
            goto out;
        }
    }

    /* convert a hex password if needed */
    result = password_util_to_auth(&ctx->session_data.hmac, is_hex_passwd,
            "key handle", &ctx->session_data.hmac);
    if (!result) {
        goto out;
    }

    result = true;

out:
    free(contextKeyFile);
    return result;
}

ENTRY_POINT(hmac) {

    (void)opts;
    (void)envp;

    tpm_hmac_ctx ctx = {
            .session_data = { 0 },
            .key_handle = 0,
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return do_hmac_and_output(&ctx) != true;
}
