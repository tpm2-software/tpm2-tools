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

#include <limits.h>
#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_hmac_ctx tpm_hmac_ctx;
struct tpm_hmac_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    char *hmac_output_file_path;
    const char *context_arg;
    tpm2_loaded_object key_context_object;
    FILE *input;
    struct {
        UINT8 P : 1;
    } flags;
    char *key_auth_str;
};

static tpm_hmac_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
};

static bool tpm_hmac_file(ESYS_CONTEXT *ectx, TPM2B_DIGEST **result) {

    TSS2_RC rval;
    unsigned long file_size = 0;
    FILE *input = ctx.input;
    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.key_context_object.tr_handle,
                            &ctx.auth.session_data, ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return false;
    }

    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /* If we can get the file size and its less than 1024, just do it in one hash invocation */
    if (res && file_size <= TPM2_MAX_DIGEST_BUFFER) {

        TPM2B_MAX_BUFFER buffer = { .size = file_size };

        res = files_read_bytes(ctx.input, buffer.buffer, buffer.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return false;
        }

        rval = Esys_HMAC(ectx, ctx.key_context_object.tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &buffer, TPM2_ALG_NULL, result);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Esys_HMAC, rval);
            return false;
        }

        return true;
    }

    TPM2B_AUTH null_auth = { .size = 0 };
    ESYS_TR sequence_handle;

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    rval = Esys_HMAC_Start(ectx, ctx.key_context_object.tr_handle,
            shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
            &null_auth, TPM2_ALG_NULL, &sequence_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_HMAC_Start, rval);
        return false;
    }

    /* If we know the file size, we decrement the amount read and terminate the
     * loop when 1 block is left, else we go till feof.
     */
    size_t left = file_size;
    bool use_left = !!res;

    TPM2B_MAX_BUFFER data;

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
        rval = Esys_SequenceUpdate(ectx, sequence_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &data);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Eys_SequenceUpdate, rval);
            return rval;
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

    rval = Esys_SequenceComplete(ectx, sequence_handle,
            shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
            &data, TPM2_RH_NULL, result, NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SequenceComplete, rval);
        return false;
    }

    return true;
}


static bool do_hmac_and_output(ESYS_CONTEXT *ectx) {

    TPM2B_DIGEST *hmac_out = NULL;
    bool res = tpm_hmac_file(ectx, &hmac_out);
    bool retval = true;

    if (!res || !hmac_out) {
        retval = false;
        goto out;
    }

    if (hmac_out->size) {
        UINT16 i;
        for (i = 0; i < hmac_out->size; i++) {
            tpm2_tool_output("%02x", hmac_out->buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    if (ctx.hmac_output_file_path) {
        retval = files_save_bytes_to_file(ctx.hmac_output_file_path, hmac_out->buffer,
            hmac_out->size);
    }

out:
    free(hmac_out);

    return retval;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.context_arg = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.key_auth_str = value;
        break;
    case 'o':
        ctx.hmac_output_file_path = value;
        break;
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Expected 1 hmac input file, got: %d", argc);
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

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "key-context",          required_argument, NULL, 'C' },
        { "auth-key",             required_argument, NULL, 'P' },
        { "out-file",             required_argument, NULL, 'o' },
    };

    ctx.input = stdin;

    *opts = tpm2_options_new("C:P:o:", ARRAY_LEN(topts), topts, on_option,
                             on_args, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    /*
     * Option C must be specified.
     */
    if (!ctx.context_arg) {
        LOG_ERR("Must specify options C.");
        return -1;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.key_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid key handle authorization, got\"%s\"",
                ctx.key_auth_str);
            return rc;
        }
    }

    result = tpm2_util_object_load(ectx, ctx.context_arg,
                                &ctx.key_context_object);
    if (!result) {
        goto out;
    }

    result = do_hmac_and_output(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    if (ctx.input && ctx.input != stdin) {
        fclose(ctx.input);
    }

    result = tpm2_session_save(ectx, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
