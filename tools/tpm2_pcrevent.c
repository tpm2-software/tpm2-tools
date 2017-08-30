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

#include <sapi/tpm20.h>

#include "../lib/tpm2_options.h"
#include "log.h"
#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_pcrevent_ctx tpm_pcrevent_ctx;
struct tpm_pcrevent_ctx {
    TPMI_DH_PCR pcr;
    FILE *input;
    TPMS_AUTH_COMMAND session_data;
    TSS2_SYS_CONTEXT *sapi_context;
};

#define TSS2_APP_PCREVENT_RC_FAILED (0x57 + 0x100 + TSS2_APP_ERROR_LEVEL)

static inline void swap_auths(TPMS_AUTH_COMMAND **auths) {

    TPMS_AUTH_COMMAND *tmp = auths[0];
    auths[0] = auths[1];
    auths[1] = tmp;
}

static TPM_RC tpm_pcrevent_file(tpm_pcrevent_ctx *ctx, TPML_DIGEST_VALUES *result) {

    TPMS_AUTH_COMMAND empty_auth = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW);

    TPMS_AUTH_COMMAND *all_auths[] = {
        &ctx->session_data, /* auth for the pcr handle */
        &empty_auth,        /* auth for the sequence handle */

    };

    TSS2_SYS_CMD_AUTHS cmd_auth_array = TSS2_SYS_CMD_AUTHS_INIT(all_auths);
    /*
     * All the routines up to complete only use one of the two handles,
     * so set size to 0
     */
    cmd_auth_array.cmdAuthsCount = 1;

    unsigned long file_size = 0;

    FILE *input = ctx->input;

    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /* If we can get the file size and its less than 1024, just do it in one hash invocation */
    if (res && file_size <= BUFFER_SIZE(TPM2B_EVENT, buffer)) {

        TPM2B_EVENT buffer = TPM2B_INIT(file_size);

        res = files_read_bytes(ctx->input, buffer.t.buffer, buffer.t.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return TSS2_APP_PCREVENT_RC_FAILED;
        }

        return Tss2_Sys_PCR_Event(ctx->sapi_context, ctx->pcr, &cmd_auth_array,
                &buffer, result,
                NULL);
    }

    TPMI_DH_OBJECT sequence_handle;
    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    TPM_RC rval = Tss2_Sys_HashSequenceStart(ctx->sapi_context, NULL, &nullAuth,
    TPM_ALG_NULL, &sequence_handle, NULL);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_HashSequenceStart failed: 0x%X", rval);
        return rval;
    }

    /* If we know the file size, we decrement the amount read and terminate the loop
     * when 1 block is left, else we go till feof.
     */
    size_t left = file_size;
    bool use_left = !!res;

    TPM2B_MAX_BUFFER data;

    /*
     * swap the auths (leave count 1) so that
     * the sequence auth is used
     * for the update call.
     */
    swap_auths(all_auths);

    bool done = false;
    while (!done) {

        size_t bytes_read = fread(data.t.buffer, 1,
                BUFFER_SIZE(typeof(data), buffer), input);
        if (ferror(input)) {
            LOG_ERR("Error reading from input file");
            return TSS2_APP_PCREVENT_RC_FAILED;
        }

        data.t.size = bytes_read;

        /* if data was read, update the sequence */
        rval = Tss2_Sys_SequenceUpdate(ctx->sapi_context, sequence_handle,
                &cmd_auth_array, &data, NULL);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Tss2_Sys_SequenceUpdate failed: 0x%X", rval);
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
            return TSS2_APP_PCREVENT_RC_FAILED;
        }
    } else {
        data.t.size = 0;
    }

    /*
     * Swap back so the order is correct for the complete call
     * and update the size to 2, as complete needs both the PCR
     * and the sequence auths.
     */
    swap_auths(all_auths);
    cmd_auth_array.cmdAuthsCount = 2;

    return Tss2_Sys_EventSequenceComplete(ctx->sapi_context, ctx->pcr,
            sequence_handle, &cmd_auth_array, &data, result, NULL);
}

static bool do_hmac_and_output(tpm_pcrevent_ctx *ctx) {

    TPML_DIGEST_VALUES digests;
    TPM_RC rval = tpm_pcrevent_file(ctx, &digests);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_pcrevent_file() failed: 0x%X", rval);
        return false;
    }

    UINT32 i;
    for (i = 0; i < digests.count; i++) {
        TPMT_HA *d = &digests.digests[i];

        tpm2_tool_output("%s:", tpm2_alg_util_algtostr(d->hashAlg));

        BYTE *bytes;
        size_t size;
        switch (d->hashAlg) {
        case TPM_ALG_SHA1:
            bytes = d->digest.sha1;
            size = sizeof(d->digest.sha1);
            break;
        case TPM_ALG_SHA256:
            bytes = d->digest.sha256;
            size = sizeof(d->digest.sha256);
            break;
        case TPM_ALG_SHA384:
            bytes = d->digest.sha384;
            size = sizeof(d->digest.sha384);
            break;
        case TPM_ALG_SHA512:
            bytes = d->digest.sha512;
            size = sizeof(d->digest.sha512);
            break;
        case TPM_ALG_SM3_256:
            bytes = d->digest.sm3_256;
            size = sizeof(d->digest.sm3_256);
            break;
        default: {
            LOG_WARN("Unknown digest to convert!");
            // print something so the format doesn't change
            // on this case.
            static BYTE byte = 0;
            bytes = &byte;
            size = sizeof(byte);
        }
        }

        size_t j;
        for (j = 0; j < size; j++) {
            tpm2_tool_output("%02x", bytes[j]);
        }

        tpm2_tool_output("\n");

    }

    return true;
}

static bool init(int argc, char *argv[], tpm_pcrevent_ctx *ctx) {

    static const struct option long_options[] = {
        { "pcr-index",            required_argument, NULL, 'i' },
        { "input-session-handle", required_argument, NULL, 'S' },
        { "password",             required_argument, NULL, 'P' },
        { NULL,                   no_argument,       NULL, '\0' }
    };

    union {
        struct {
            UINT8 i : 1;
            UINT8 S : 1;
            UINT8 P : 1;
            UINT8 unused : 5;
        };
        UINT8 all;
    } flags = { .all = 0 };

    int opt;
    bool res;
    while ((opt = getopt_long(argc, argv, "i:P:S:", long_options, NULL))
            != -1) {
        switch (opt) {
        case 'i':
            res = tpm2_util_string_to_uint32(optarg, &ctx->pcr);
            if (!res) {
                LOG_ERR("Could not convert \"%s\", to a pcr index.", argv[1]);
                return false;
            }
            flags.i = 1;
            break;
        case 'S': {
            bool result = tpm2_util_string_to_uint32(optarg,
                    &ctx->session_data.sessionHandle);
            if (!result) {
                LOG_ERR(
                        "Could not convert session handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
        }
            flags.S = 1;
            break;
        case 'P': {
            bool result = tpm2_password_util_from_optarg(optarg,
                    &ctx->session_data.hmac);
            if (!result) {
                LOG_ERR("Invalid key handle password, got\"%s\"", optarg);
                return false;
            }
        }
            flags.P = 1;
            break;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??", opt);
            return false;
        }
    }

    if (flags.S && flags.P) {
        LOG_ERR("Cannot specify both -P and -S options.");
        return false;
    }

    if ((flags.S || flags.P) && !flags.i) {
        LOG_ERR("Must specify a PCR index via -i with the -%c option.",
                flags.P ? 'P' : 'S');
        return false;
    }

    size_t cnt = argc - optind;
    if (cnt > 1) {
        LOG_ERR("Expected a single FILE argument, got: %zu", cnt);
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

    (void) opts;
    (void) envp;

    int rc = 1;

    tpm_pcrevent_ctx ctx = {
            .pcr = TPM_RH_NULL,
            .input = stdin,
            .session_data = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW),
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
