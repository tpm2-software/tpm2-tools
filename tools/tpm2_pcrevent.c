/* SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_auth_util.h"
#include "tpm2_tool.h"

typedef struct tpm_pcrevent_ctx tpm_pcrevent_ctx;
struct tpm_pcrevent_ctx {
    struct {
        const char *auth_str;
        tpm2_session *session;
    } auth;
    ESYS_TR pcr;
    FILE *input;
};

static tpm_pcrevent_ctx ctx = {
    .pcr = ESYS_TR_RH_NULL,
};

static tool_rc tpm_pcrevent_file(ESYS_CONTEXT *ectx,
        TPML_DIGEST_VALUES **result) {

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
            return tool_rc_general_error;
        }

        return tpm2_pcr_event(ectx, ctx.pcr, ctx.auth.session, &buffer, result);
    }

    ESYS_TR sequence_handle;
    TPM2B_AUTH null_auth = TPM2B_EMPTY_INIT;

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    tool_rc rc = tpm2_hash_sequence_start(ectx, &null_auth, TPM2_ALG_NULL,
            &sequence_handle);
    if (rc != tool_rc_success) {
        return rc;
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
            return tool_rc_general_error;
        }

        data.size = bytes_read;

        /* if data was read, update the sequence */
        rc = tpm2_sequence_update(ectx, sequence_handle, &data);
        if (rc != tool_rc_success) {
            return rc;
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
            return tool_rc_general_error;
        }
    } else {
        data.size = 0;
    }

    return tpm2_event_sequence_complete(ectx, ctx.pcr, sequence_handle,
            ctx.auth.session, &data, result);
}

static tool_rc do_pcrevent_and_output(ESYS_CONTEXT *ectx) {

    TPML_DIGEST_VALUES *digests = NULL;
    tool_rc rc = tpm_pcrevent_file(ectx, &digests);
    if (rc != tool_rc_success) {
        return rc;
    }

    assert(digests);

    UINT32 i;
    for (i = 0; i < digests->count; i++) {
        TPMT_HA *d = &digests->digests[i];

        tpm2_tool_output("%s: ",
                tpm2_alg_util_algtostr(d->hashAlg, tpm2_alg_util_flags_hash));

        const BYTE *bytes;
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
            static const BYTE byte = 0;
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

    free(digests);
    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 2) {
        LOG_ERR("Expected FILE and PCR index at most, got %d", argc);
        return false;
    }

    FILE *f = NULL;
    const char *pcr = NULL;

    unsigned i;
    /* argc can never be negative so cast is safe */
    for (i = 0; i < (unsigned) argc; i++) {

        FILE *x = fopen(argv[i], "rb");
        /* file already found but got another file */
        if (f && x) {
            LOG_ERR("Only expected one file input");
            fclose(x);
            goto error;
            /* looking for file and got a file so assign */
        } else if (x && !f) {
            f = ctx.input = x;
            /* looking for pcr and not a file */
        } else if (!pcr) {
            pcr = argv[i];
            bool result = tpm2_util_handle_from_optarg(pcr, &ctx.pcr,
                    TPM2_HANDLE_FLAGS_PCR);
            if (!result) {
                LOG_ERR("Could not convert \"%s\", to a pcr index.", pcr);
                return false;
            }

            /* got pcr and not a file (another pcr) */
        } else {
            LOG_ERR("Already got PCR index.");
            goto error;
        }
    }

    return true;

error:
    if (f) {
        fclose(f);
    }

    return false;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.auth.auth_str = value;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "auth",      required_argument, NULL, 'P' },
    };

    *opts = tpm2_options_new("P:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    ctx.input = ctx.input ? ctx.input : stdin;

    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key handle authorization");
        return rc;
    }

    return do_pcrevent_and_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth.session);
}

static void tpm2_tool_onexit(void) {

    if (ctx.input && ctx.input != stdin) {
        fclose(ctx.input);
    }
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrevent", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, tpm2_tool_onexit)
