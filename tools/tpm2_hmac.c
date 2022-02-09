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

#define MAX_SESSIONS 3
typedef struct tpm_hmac_ctx tpm_hmac_ctx;
struct tpm_hmac_ctx {
    /*
     * Inputs
     */
    struct {
        char *ctx_path;
        char *auth_str;
        tpm2_loaded_object object;
    } hmac_key;

    FILE *input;
    unsigned long input_file_size;

    TPMI_ALG_HASH halg;
    bool hex;
    bool is_not_sequence;

    /*
     * Outputs
     */
    char *hmac_output_file_path;
    TPM2B_DIGEST *hmac_out;
    char *ticket_path;
    TPMT_TK_HASHCHECK *validation;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_hmac_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc hmac(ESYS_CONTEXT *ectx) {

    unsigned long file_size = 0;
    FILE *input = ctx.input;
    /* Suppress error reporting with NULL path */
    bool is_file_readable = files_get_file_size(input, &file_size, 0);
    /*
     * If we can get the file size and its less than 1024, just do it in one
     * hash invocation.
     *
     * We can't use the one-shot command if we require ticket, as it doesn't
     * provide it in the response from the TPM.
     */
    tool_rc rc = tool_rc_success;
    bool is_file_op_success = false;
    if (!ctx.ticket_path && is_file_readable &&
        file_size <= TPM2_MAX_DIGEST_BUFFER) {
        TPM2B_MAX_BUFFER buffer = { .size = file_size };

        is_file_readable = files_read_bytes(ctx.input, buffer.buffer,
            buffer.size);
        if (!is_file_readable) {
            LOG_ERR("Error reading input file!");
            return tool_rc_general_error;
        }

        /*
         * hash algorithm specified in the key's scheme is used as the
         * hash algorithm for the HMAC
         */
        return tpm2_hmac(ectx, &ctx.hmac_key.object, ctx.halg, &buffer,
            &ctx.hmac_out, &ctx.cp_hash, ctx.parameter_hash_algorithm);
    }

    if (ctx.cp_hash_path) {
        LOG_ERR("Cannot calculate cpHash for buffers requiring HMAC sequence.");
        return tool_rc_general_error;
    }

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    ESYS_TR sequence_handle;
    rc = tpm2_hmac_start(ectx, &ctx.hmac_key.object, ctx.halg,
        &sequence_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* If we know the file size, we decrement the amount read and terminate the
     * loop when 1 block is left, else we go till feof.
     */
    size_t left = file_size;
    bool use_left = is_file_readable;
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
        is_file_op_success = files_read_bytes(input, data.buffer, left);
        if (!is_file_op_success) {
            LOG_ERR("Error reading from input file.");
            return tool_rc_general_error;
        }
    } else {
        data.size = 0;
    }

    return tpm2_hmac_sequencecomplete(ectx, sequence_handle,
        &ctx.hmac_key.object, &data, &ctx.hmac_out, &ctx.validation);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    FILE *out = stdout;
    assert(ctx.hmac_out);
    if (ctx.ticket_path) {
        is_file_op_success = files_save_validation(ctx.validation,
            ctx.ticket_path);
        if (!is_file_op_success) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    if (ctx.hmac_output_file_path) {
        out = fopen(ctx.hmac_output_file_path, "wb+");
        if (!out) {
            LOG_ERR("Could not open output file \"%s\", error: %s",
                    ctx.hmac_output_file_path, strerror(errno));
            rc = tool_rc_general_error;
            goto out;
        }
    } else if (!output_enabled) {
        rc = tool_rc_success;
        goto out;
    }

    if (ctx.hex) {
        tpm2_util_print_tpm2b2(out, ctx.hmac_out);
    } else {
        is_file_op_success = files_write_bytes(out, ctx.hmac_out->buffer,
            ctx.hmac_out->size);
        if (!is_file_op_success) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

out:
    if (out && out != stdout) {
        fclose(out);
    }

    return rc;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.hmac_key.ctx_path,
        ctx.hmac_key.auth_str, &ctx.hmac_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key handle authorization");
        return rc;
    }

    /* Object #2 */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * if no halg was specified, read the public portion of the key and use it's
     * scheme
     */
    if (!ctx.halg) {
        TPM2B_PUBLIC *pub = 0;
        rc = tpm2_readpublic(ectx, ctx.hmac_key.object.tr_handle, &pub, 0, 0);
        if (rc != tool_rc_success) {
            return rc;
        }

        /*
         * if we're attempting to figure out a hashing scheme, and the scheme is NULL
         * we default to sha256.
         */
        ctx.halg = pub->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
        if (ctx.halg == TPM2_ALG_NULL) {
            ctx.halg = TPM2_ALG_SHA256;
        }
        free(pub);
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.hmac_key.object.session,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (!ctx.hmac_key.ctx_path) {
        LOG_ERR("Must specify options C.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
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
        { "key-context",    required_argument, 0, 'c' },
        { "auth",           required_argument, 0, 'p' },
        { "output",         required_argument, 0, 'o' },
        { "hash-algorithm", required_argument, 0, 'g' },
        { "ticket",         required_argument, 0, 't' },
        { "hex",            no_argument,       0,  0  },
        { "cphash",         required_argument, 0,  1  },
    };

    ctx.input = stdin;

    *opts = tpm2_options_new("c:p:o:g:t:", ARRAY_LEN(topts), topts, on_option,
        on_args, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = hmac(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    if (ctx.input && ctx.input != stdin) {
        fclose(ctx.input);
    }
    free(ctx.hmac_out);
    free(ctx.validation);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.hmac_key.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("hmac", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
