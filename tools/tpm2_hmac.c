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
#include "tpm2_tool.h"

typedef struct tpm_hmac_ctx tpm_hmac_ctx;
struct tpm_hmac_ctx {
    struct {
        char *ctx_path;
        char *auth_str;
        tpm2_loaded_object object;
    } hmac_key;

    FILE *input;
    char *hmac_output_file_path;
    char *ticket_path;
    TPMI_ALG_HASH halg;
    bool hex;
    char *cp_hash_path;
};

static tpm_hmac_ctx ctx;

static tool_rc tpm_hmac_file(ESYS_CONTEXT *ectx, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation) {

    unsigned long file_size = 0;
    FILE *input = ctx.input;

    tool_rc rc;
    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /*
     * If we can get the file size and its less than 1024, just do it in one hash invocation.
     * We can't use the one-shot command if we require ticket, as it doesn't provide it in
     * the response from the TPM.
     */
    if (!ctx.ticket_path && res && file_size <= TPM2_MAX_DIGEST_BUFFER) {

        TPM2B_MAX_BUFFER buffer = { .size = file_size };

        res = files_read_bytes(ctx.input, buffer.buffer, buffer.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return tool_rc_general_error;
        }

        if (ctx.cp_hash_path) {
            LOG_WARN("Exiting without performing HMAC when calculating cpHash");
            TPM2B_DIGEST cp_hash = { .size = 0 };
            tool_rc rc = tpm2_hmac(ectx, &ctx.hmac_key.object, ctx.halg,
            &buffer, result, &cp_hash);
            if (rc != tool_rc_success) {
                return rc;
            }

            bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
            if (!result) {
                rc = tool_rc_general_error;
            }
            return rc;
        }
        /*
         * hash algorithm specified in the key's scheme is used as the
         * hash algorithm for the HMAC
         */
        return tpm2_hmac(ectx, &ctx.hmac_key.object, ctx.halg, &buffer, result,
        NULL);
    }

    if (ctx.cp_hash_path) {
        LOG_ERR("Cannot calculate cpHash for buffers requiring HMAC sequence.");
        return tool_rc_general_error;
    }

    ESYS_TR sequence_handle;
    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    rc = tpm2_hmac_start(ectx, &ctx.hmac_key.object, ctx.halg,
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
        rc = tpm2_hmac_sequenceupdate(ectx, sequence_handle,
                &ctx.hmac_key.object, &data);
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

    rc = tpm2_hmac_sequencecomplete(ectx, sequence_handle, &ctx.hmac_key.object,
            &data, result, validation);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tool_rc_success;
}

static tool_rc do_hmac_and_output(ESYS_CONTEXT *ectx) {

    TPM2B_DIGEST *hmac_out = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    FILE *out = stdout;

    tool_rc rc = tpm_hmac_file(ectx, &hmac_out, &validation);
    if (rc != tool_rc_success || ctx.cp_hash_path) {
        goto out;
    }

    assert(hmac_out);

    if (ctx.ticket_path) {
        bool res = files_save_validation(validation, ctx.ticket_path);
        if (!res) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    rc = tool_rc_general_error;
    if (ctx.hmac_output_file_path) {
        out = fopen(ctx.hmac_output_file_path, "wb+");
        if (!out) {
            LOG_ERR("Could not open output file \"%s\", error: %s",
                    ctx.hmac_output_file_path, strerror(errno));
            goto out;
        }
    } else if (!output_enabled) {
        rc = tool_rc_success;
        goto out;
    }

    if (ctx.hex) {
        tpm2_util_print_tpm2b2(out, hmac_out);
    } else {

        bool res = files_write_bytes(out, hmac_out->buffer, hmac_out->size);
        if (!res) {
            goto out;
        }
    }

    rc = tool_rc_success;

out:
    if (out && out != stdout) {
        fclose(out);
    }

    free(hmac_out);
    free(validation);
    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.hmac_key.ctx_path = value;
        break;
    case 'p':
        ctx.hmac_key.auth_str = value;
        break;
    case 'o':
        ctx.hmac_output_file_path = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            return false;
        }
        break;
    case 't':
        ctx.ticket_path = value;
        break;
    case 0:
        ctx.hex = true;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
        /* no default */
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

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "key-context",    required_argument, NULL, 'c' },
        { "auth",           required_argument, NULL, 'p' },
        { "output",         required_argument, NULL, 'o' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "ticket",         required_argument, NULL, 't' },
        { "hex",            no_argument,       NULL,  0  },
        { "cphash",         required_argument, NULL,  1  },
    };

    ctx.input = stdin;

    *opts = tpm2_options_new("c:p:o:g:t:", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc readpub(ESYS_CONTEXT *ectx, ESYS_TR handle,
        TPM2B_PUBLIC **public) {

    return tpm2_readpublic(ectx, handle, public, NULL, NULL);
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * Option C must be specified.
     */
    if (!ctx.hmac_key.ctx_path) {
        LOG_ERR("Must specify options C.");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.hmac_key.ctx_path,
            ctx.hmac_key.auth_str, &ctx.hmac_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key handle authorization");
        return rc;
    }

    /*
     * if no halg was specified, read the public portion of the key and use it's
     * scheme
     */
    if (!ctx.halg) {
        TPM2B_PUBLIC *pub = NULL;
        rc = readpub(ectx, ctx.hmac_key.object.tr_handle, &pub);
        if (rc != tool_rc_success) {
            return rc;
        }

        /*
         * if we're attempting to figure out a hashing scheme, and the scheme is NULL
         * we default to sha256.
         */
        ctx.halg =
                pub->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
        if (ctx.halg == TPM2_ALG_NULL) {
            ctx.halg = TPM2_ALG_SHA256;
        }

        free(pub);
    }

    return do_hmac_and_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    if (ctx.input && ctx.input != stdin) {
        fclose(ctx.input);
    }

    return tpm2_session_close(&ctx.hmac_key.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("hmac", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
