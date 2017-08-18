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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"
#include "tpm_hash.h"
#include "tpm2_alg_util.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    union {
        struct {
            uint8_t key_handle :1;
            uint8_t digest :1;
            uint8_t halg :1;
            uint8_t msg :1;
            uint8_t raw :1;
            uint8_t sig :1;
            uint8_t ticket :1;
            uint8_t key_context :1;
        };
        uint8_t all;
    } flags;
    TPMI_ALG_HASH halg;
    TPM2B_DIGEST msgHash;
    TPMI_DH_OBJECT keyHandle;
    TPMT_SIGNATURE signature;
    char *msg_file_path;
    char *sig_file_path;
    char *out_file_path;
    char *context_key_file_path;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool verify_signature(tpm2_verifysig_ctx *ctx) {

    UINT32 rval;
    TPMT_TK_VERIFIED validation;

    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    UINT16 i;
    for (i = 0; i < ctx->msgHash.t.size; i++)
        printf("%02x ", ctx->msgHash.t.buffer[i]);
    printf("\n");

    rval = Tss2_Sys_VerifySignature(ctx->sapi_context, ctx->keyHandle, NULL,
            &ctx->msgHash, &ctx->signature, &validation, &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_VerifySignature failed, error code: 0x%x\n", rval);
        return false;
    }

    /* TODO fix serialization */
    return files_save_bytes_to_file(ctx->out_file_path, (UINT8 *) &validation,
            sizeof(validation));
}

static TPM2B *message_from_file(const char *msg_file_path) {

    unsigned long size;

    bool result = files_get_file_size(msg_file_path, &size);
    if (!result) {
        return NULL;
    }

    if (!size) {
        LOG_ERR("The msg file \"%s\" is empty", msg_file_path);
        return NULL;
    }

    TPM2B *msg = (TPM2B *) calloc(1, sizeof(TPM2B) + size);
    if (!msg) {
        LOG_ERR("OOM");
        return NULL;
    }

    UINT16 tmp = msg->size = size;
    if (!files_load_bytes_from_file(msg_file_path, msg->buffer, &tmp)) {
        free(msg);
        return NULL;
    }
    return msg;
}

static bool generate_signature(tpm2_verifysig_ctx *ctx) {

    UINT16 size;
    UINT8 *buffer;

    if (ctx->flags.raw) {
        ctx->signature.sigAlg = TPM_ALG_RSASSA;
        ctx->signature.signature.rsassa.hash = ctx->halg;
        ctx->signature.signature.rsassa.sig.t.size =
                sizeof(ctx->signature.signature.rsassa.sig) - 2;

        buffer = ctx->signature.signature.rsassa.sig.t.buffer;
        size = ctx->signature.signature.rsassa.sig.t.size;
    } else {
        size = sizeof(ctx->signature);
        buffer = (UINT8 *) &ctx->signature;
    }

    bool result = files_load_bytes_from_file(ctx->sig_file_path, buffer, &size);
    if (!result) {
        LOG_ERR("Could not create %s signature from file: \"%s\"",
                ctx->flags.raw ? "raw" : "\0", ctx->sig_file_path);
    }
    return result;
}

static bool init(tpm2_verifysig_ctx *ctx) {

    TPM2B *msg = NULL;
    bool return_value = false;

    if (ctx->flags.msg) {
        msg = message_from_file(ctx->msg_file_path);
        if (!msg) {
            /* message_from_file() logs specific error no need to here */
            return false;
        }
    }

    if (ctx->flags.sig) {
        bool res = generate_signature(ctx);
        if (!res) {
            goto err;
        }
    }

    if (ctx->flags.key_context) {
        bool result = files_load_tpm_context_from_file(ctx->sapi_context, &ctx->keyHandle,
                ctx->context_key_file_path);
        if (!result) {
            goto err;
        }
    }

    /* If no digest is specified, compute it */
    if (!ctx->flags.digest) {
        if (!ctx->flags.msg) {
            /*
             * This is a redundant check since main() checks this case, but we'll add it here to silence any
             * complainers.
             */
            LOG_ERR("No digest set and no message file to compute from, cannot compute message hash!");
            goto err;
        }
        int rc = tpm_hash_compute_data(ctx->sapi_context, msg->buffer, msg->size,
                ctx->halg, &ctx->msgHash);
        if (rc) {
            LOG_ERR("Compute message hash failed!\n");
            goto err;
        }
    }
    return_value = true;

err:
    free(msg);
    return return_value;
}

static bool handle_options_and_init(int argc, char *argv[], tpm2_verifysig_ctx *ctx) {

    const char *optstring = "k:g:m:D:rs:t:c:";
    const struct option long_options[] = {
            { "keyHandle",  1, NULL, 'k' },
            { "digest",     1, NULL, 'D' },
            { "halg",       1, NULL, 'g' },
            { "msg",        1, NULL, 'm' },
            { "raw",        0, NULL, 'r' },
            { "sig",        1, NULL, 's' },
            { "ticket",     1, NULL, 't' },
            { "keyContext", 1, NULL, 'c' },
            { NULL,         0, NULL, '\0' }
    };

    if (argc == 1) {
        LOG_ERR("Invalid usage. Try --help for help.");
        return false;
    }

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        case 'k': {
            bool res = tpm2_util_string_to_uint32(optarg, &ctx->keyHandle);
            if (!res) {
                LOG_ERR("Unable to convert key handle, got: \"%s\"", optarg);
                return false;
            }
            ctx->flags.key_handle = 1;
        }
            break;
        case 'g': {
            ctx->halg = tpm2_alg_util_from_optarg(optarg);
            if (ctx->halg == TPM_ALG_ERROR) {
                LOG_ERR("Unable to convert algorithm, got: \"%s\"", optarg);
                return false;
            }
            ctx->flags.halg = 1;
        }
            break;
        case 'm': {
            ctx->msg_file_path = optarg;
            ctx->flags.msg = 1;
        }
            break;
        case 'D': {
            UINT16 size = sizeof(ctx->msgHash);
            if (!files_load_bytes_from_file(optarg, (UINT8 *) &ctx->msgHash, &size)) {
                LOG_ERR("Could not load digest from file!");
                return false;
            }
            ctx->flags.digest = 1;
        }
            break;
        case 'r':
            ctx->flags.raw = 1;
            break;
        case 's':
            ctx->sig_file_path = optarg;
            ctx->flags.sig = 1;
            break;
        case 't':
            ctx->out_file_path = optarg;

            if (files_does_file_exist(ctx->out_file_path)) {
                return false;
            }
            ctx->flags.ticket = 1;
            break;
        case 'c':
            ctx->context_key_file_path = optarg;
            ctx->flags.key_context = 1;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            break;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            break;
            /* no default */
        }
    };

    /* check flags for mismatches */
    if (ctx->flags.digest && (ctx->flags.msg || ctx->flags.halg)) {
        LOG_ERR(
                "Cannot specify --digest (-D) and ( --msg (-m) or --halg (-g) )");
        return false;
    }

    if (!((ctx->flags.key_handle || ctx->flags.key_context) && ctx->flags.sig
            && ctx->flags.ticket)) {
        LOG_ERR(
                "--keyHandle (-k) or --keyContext (-c) and --sig (-s) and --ticket (-t) must be specified");
        return false;
    }

    /* initialize and process */
    return init(ctx);
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void) opts;
    (void) envp;

    int normalized_return_code = 1;

    tpm2_verifysig_ctx ctx = {
            .flags = { .all = 0 },
            .halg = TPM_ALG_SHA1,
            .msgHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
            .sig_file_path = NULL,
            .msg_file_path = NULL,
            .out_file_path = NULL,
            .context_key_file_path = NULL,
            .sapi_context = sapi_context
    };

    bool res = handle_options_and_init(argc, argv, &ctx);
    if (!res) {
        return normalized_return_code;
    }

    res = verify_signature(&ctx);
    if (!res) {
        LOG_ERR("Verify signature failed!");
        return normalized_return_code;
    }

    return 0;
}
