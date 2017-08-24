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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <limits.h>
#include <sapi/tpm20.h>

#include "tpm2_password_util.h"
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
    FILE *input;
    TSS2_SYS_CONTEXT *sapi_context;
};

#define TSS2_APP_HMAC_RC_FAILED (0x42 + 0x100 + TSS2_APP_ERROR_LEVEL)

TPM_RC tpm_hmac_file(tpm_hmac_ctx *ctx, TPM2B_DIGEST *result) {

    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    session_data_array[0] = &ctx->session_data;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    unsigned long file_size = 0;

    FILE *input = ctx->input;

    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /* If we can get the file size and its less than 1024, just do it in one hash invocation */
    if (res && file_size <= MAX_DIGEST_BUFFER) {

        TPM2B_MAX_BUFFER buffer = { .t = { .size = file_size }, };

        res = files_read_bytes(ctx->input, buffer.t.buffer, buffer.t.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return TSS2_APP_HMAC_RC_FAILED;
        }

        return Tss2_Sys_HMAC(ctx->sapi_context, ctx->key_handle,
                &sessions_data, &buffer, ctx->algorithm, result,
                &sessions_data_out);
    }

    TPM2B_AUTH null_auth = { .t.size = 0 };
    TPMI_DH_OBJECT sequence_handle;

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    TPM_RC rval = Tss2_Sys_HMAC_Start(ctx->sapi_context, ctx->key_handle, &sessions_data,
            &null_auth, ctx->algorithm, &sequence_handle, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_HMAC_Start failed: 0x%X", rval);
        return rval;
    }

    /* If we know the file size, we decrement the amount read and terminate the loop
     * when 1 block is left, else we go till feof.
     */
    size_t left = file_size;
    bool use_left = !!res;

    TPM2B_MAX_BUFFER data;

    bool done = false;
    while (!done) {

        size_t bytes_read = fread(data.t.buffer, 1,
                BUFFER_SIZE(typeof(data), buffer), input);
        if (ferror(input)) {
            LOG_ERR("Error reading from input file");
            return TSS2_APP_HMAC_RC_FAILED;
        }

        data.t.size = bytes_read;

        /* if data was read, update the sequence */
        rval = Tss2_Sys_SequenceUpdate(ctx->sapi_context, sequence_handle,
                &sessions_data, &data, &sessions_data_out);
        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }

        if (use_left) {
            left -= bytes_read;
            if (left <= MAX_DIGEST_BUFFER) {
                done = true;
                continue;
            }
        } else if (feof(input)) {
            done = true;
        }
    } /* end file read/hash update loop */

    if (use_left) {
        data.t.size = left;
        bool res = files_read_bytes(input, data.t.buffer, left);
        if (!res) {
            LOG_ERR("Error reading from input file.");
            return TSS2_APP_HMAC_RC_FAILED;
        }
    } else {
        data.t.size = 0;
    }

    return Tss2_Sys_SequenceComplete(ctx->sapi_context, sequence_handle,
            &sessions_data, &data, TPM_RH_NULL, result, NULL,
            &sessions_data_out);
}


static bool do_hmac_and_output(tpm_hmac_ctx *ctx) {

    TPM2B_DIGEST hmac_out = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM_RC rval = tpm_hmac_file(ctx, &hmac_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_hmac_file() failed: 0x%X", rval);
        return false;
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
    char *contextKeyFile = NULL;

    const char *optstring = "k:P:g:o:S:c:";
    static struct option long_options[] = {
        {"keyHandle",   required_argument, NULL, 'k'},
        {"keyContext",  required_argument, NULL, 'c'},
        {"pwdk",        required_argument, NULL, 'P'},
        {"algorithm",   required_argument, NULL, 'g'},
        {"outfile",     required_argument, NULL, 'o'},
        {"input-session-handle",1,         NULL, 'S'},
        {NULL,          no_argument,       NULL, '\0'}
    };

    union {
        struct {
            UINT8 k : 1;
            UINT8 P : 1;
            UINT8 g : 1;
            UINT8 o : 1;
            UINT8 c : 1;
            UINT8 unused : 3;
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
            result = tpm2_password_util_from_optarg(optarg, &ctx->session_data.hmac);
            if (!result) {
                LOG_ERR("Invalid key handle password, got\"%s\"", optarg);
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
        case 'S':
            if (!tpm2_util_string_to_uint32(optarg, &ctx->session_data.sessionHandle)) {
                LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
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
    }

    /*
     * Options g, I, o must be specified and k or c must be specified.
     */
    if (!((flags.k || flags.c) && flags.o && flags.g)) {
        LOG_ERR("Must specify options g, o and k or c");
        return false;
    }

    if (flags.c) {
        result = files_load_tpm_context_from_file(ctx->sapi_context, &ctx->key_handle,
                contextKeyFile);
        if (!result) {
            LOG_ERR("Loading tpm context from file \"%s\" failed.",
                    contextKeyFile);
            return false;
        }
    }

    int cnt = argc - optind;
    if (cnt > 1) {
        LOG_ERR("Expected 1 hmac input file, got: %d", cnt);
        return false;
    }

    if (cnt) {
        ctx->input = fopen(argv[optind], "rb");
        if (!ctx->input) {
            LOG_ERR("Error opening file \"%s\", error: %s", argv[optind],
                    strerror(errno));
            return false;
        }
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    int rc = 1;

    tpm_hmac_ctx ctx = {
            .session_data = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW),
            .key_handle = 0,
            .input = stdin,
            .sapi_context = sapi_context,
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        goto out;
    }

    result = do_hmac_and_output(&ctx);
    if (!result) {
        goto out;
    }

    rc = 0;
 out:
     if (ctx.input && ctx.input != stdin) {
         fclose(ctx.input);
     }
     return rc;
}
