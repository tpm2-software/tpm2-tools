//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_pcrevent_ctx tpm_pcrevent_ctx;
struct tpm_pcrevent_ctx {
    struct {
        UINT8 i : 1;
        UINT8 P : 1;
    } flags;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPMI_DH_PCR pcr;
    FILE *input;
    char *pcr_auth_str;
};

static tpm_pcrevent_ctx ctx = {
        .pcr = TPM2_RH_NULL,
        .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) }
};

static inline void swap_auths(TPMS_AUTH_COMMAND *a, TPMS_AUTH_COMMAND *b) {

    TPMS_AUTH_COMMAND tmp = *a;
    *a = *b;
    *b = tmp;
}

static bool tpm_pcrevent_file(TSS2_SYS_CONTEXT *sapi_context,
        TPML_DIGEST_VALUES *result) {

    /*
     * commands only use one of 2 values, so just swap
     * positions until all 2 need to be used
     */
    TSS2L_SYS_AUTH_COMMAND cmd_auth_array = {
        1, {
            ctx.auth.session_data,
            TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW)
         },
    };

    unsigned long file_size = 0;

    FILE *input = ctx.input;

    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /* If we can get the file size and its less than 1024, just do it in one hash invocation */
    if (res && file_size <= BUFFER_SIZE(TPM2B_EVENT, buffer)) {

        TPM2B_EVENT buffer = TPM2B_INIT(file_size);

        res = files_read_bytes(ctx.input, buffer.buffer, buffer.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return false;
        }

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PCR_Event(sapi_context, ctx.pcr, &cmd_auth_array,
                &buffer, result,
                NULL));
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_PCR_Event, rval);
            return false;
        }

        return true;
    }

    TPMI_DH_OBJECT sequence_handle;
    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_HashSequenceStart(sapi_context, NULL, &nullAuth,
    TPM2_ALG_NULL, &sequence_handle, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_HashSequenceStart, rval);
        return false;
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
    swap_auths(&cmd_auth_array.auths[0], &cmd_auth_array.auths[1]);

    bool done = false;
    while (!done) {

        size_t bytes_read = fread(data.buffer, 1,
                BUFFER_SIZE(typeof(data), buffer), input);
        if (ferror(input)) {
            LOG_ERR("Error reading from input file");
            return false;
        }

        data.size = bytes_read;

        /* if data was read, update the sequence */
        rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sapi_context, sequence_handle,
                &cmd_auth_array, &data, NULL));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_SequenceUpdate, rval);
            return false;
        }

        if (use_left) {
            left -= bytes_read;
            if (left <= TPM2_MAX_DIGEST_BUFFER) {
                done = true;
                continue;
            }
        } else if (feof(input)) {
            done = true;
        }
    } /* end file read/hash update loop */

    if (use_left) {
        data.size = left;
        bool res = files_read_bytes(input, data.buffer, left);
        if (!res) {
            LOG_ERR("Error reading from input file.");
            return false;
        }
    } else {
        data.size = 0;
    }

    /*
     * Swap back so the order is correct for the complete call
     * and update the size to 2, as complete needs both the PCR
     * and the sequence auths.
     */
    swap_auths(&cmd_auth_array.auths[0], &cmd_auth_array.auths[1]);
    cmd_auth_array.count = 2;

    rval = TSS2_RETRY_EXP(Tss2_Sys_EventSequenceComplete(sapi_context, ctx.pcr,
            sequence_handle, &cmd_auth_array, &data, result, NULL));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_EventSequenceComplete, rval);
        return false;
    }

    return true;
}

static bool do_hmac_and_output(TSS2_SYS_CONTEXT *sapi_context) {

    TPML_DIGEST_VALUES digests;
    bool res = tpm_pcrevent_file(sapi_context, &digests);
    if (!res) {
        return false;
    }

    UINT32 i;
    for (i = 0; i < digests.count; i++) {
        TPMT_HA *d = &digests.digests[i];

        tpm2_tool_output("%s: ", tpm2_alg_util_algtostr(d->hashAlg));

        BYTE *bytes;
        size_t size;
        switch (d->hashAlg) {
        case TPM2_ALG_SHA1:
            bytes = d->digest.sha1;
            size = sizeof(d->digest.sha1);
            break;
        case TPM2_ALG_SHA256:
            bytes = d->digest.sha256;
            size = sizeof(d->digest.sha256);
            break;
        case TPM2_ALG_SHA384:
            bytes = d->digest.sha384;
            size = sizeof(d->digest.sha384);
            break;
        case TPM2_ALG_SHA512:
            bytes = d->digest.sha512;
            size = sizeof(d->digest.sha512);
            break;
        case TPM2_ALG_SM3_256:
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

static bool init(void) {

    ctx.input = ctx.input ? ctx.input : stdin;

    if ((ctx.auth.session || ctx.flags.P) && !ctx.flags.i) {
        LOG_ERR("Must specify a PCR index via -i with the -%c option.",
                ctx.flags.P ? 'P' : 'S');
        return false;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Expected a single FILE argument, got: %d", argc);
        return false;
    }

    ctx.input = fopen(argv[0], "rb");
    if (!ctx.input) {
        LOG_ERR("Error opening file \"%s\", error: %s", argv[0],
                strerror(errno));
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'i': {
        bool result = tpm2_util_string_to_uint32(value, &ctx.pcr);
        if (!result) {
            LOG_ERR("Could not convert \"%s\", to a pcr index.", value);
            return false;
        }
    }
        ctx.flags.i = 1;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.pcr_auth_str = value;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "pcr-index", required_argument, NULL, 'i' },
        { "auth-pcr",  required_argument, NULL, 'P' },
    };

    *opts = tpm2_options_new("i:P:", ARRAY_LEN(topts), topts,
                             on_option, on_arg, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init();
    if (!result) {
        goto out;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.pcr_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid key handle authorization, got\"%s\"",
                ctx.pcr_auth_str);
            goto out;
        }
    }

    result = do_hmac_and_output(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    result = tpm2_session_save(sapi_context, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_tool_onexit(void) {

    if (ctx.input && ctx.input != stdin) {
        fclose(ctx.input);
    }

    tpm2_session_free(&ctx.auth.session);
}
