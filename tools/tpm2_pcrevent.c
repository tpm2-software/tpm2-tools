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

#define MAX_SESSIONS 3
typedef struct tpm_pcrevent_ctx tpm_pcrevent_ctx;
struct tpm_pcrevent_ctx {
    /*
     * Inputs
     */
    struct {
        const char *auth_str;
        tpm2_session *session;
    } auth;

    ESYS_TR pcr;
    FILE *input;
    unsigned long file_size;
    TPM2B_EVENT pcrevent_buffer;
    bool is_input_not_fifo;
    bool is_hashsequence_needed;

    /*
     * Outputs
     */
    TPML_DIGEST_VALUES *digests;
    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_pcrevent_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .pcr = ESYS_TR_RH_NULL,
};

static tool_rc pcr_hashsequence(ESYS_CONTEXT *ectx) {

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

    /*
     * If file size is non-zero we decrement the amount read and terminate the
     * loop when 1 block is left.
     *
     * If file size is reported zero we go till feof.
     */
    size_t left = ctx.file_size;
    bool is_filesize_nonzero = !!ctx.is_input_not_fifo && left;

    TPM2B_MAX_BUFFER data;
    bool done = false;
    while (!done) {

        size_t bytes_read = fread(data.buffer, 1,
                BUFFER_SIZE(typeof(data), buffer), ctx.input);
        if (ferror(ctx.input)) {
            LOG_ERR("Error reading from input file");
            return tool_rc_general_error;
        }

        data.size = bytes_read;

        /* if data was read, update the sequence */
        rc = tpm2_sequence_update(ectx, sequence_handle, &data);
        if (rc != tool_rc_success) {
            return rc;
        }

        if (is_filesize_nonzero) {
            left -= bytes_read;
            if (left <= TPM2_MAX_DIGEST_BUFFER) {
                done = true;
                continue;
            }
        } else if (feof(ctx.input)) {
            done = true;
        }
    } /* end file read/hash update loop */

    if (is_filesize_nonzero) {
        data.size = left;
        bool result = files_read_bytes(ctx.input, data.buffer, left);
        if (!result) {
            LOG_ERR("Error reading from input file.");
            return tool_rc_general_error;
        }
    } else {
        data.size = 0;
    }

    return tpm2_event_sequence_complete(ectx, ctx.pcr, sequence_handle,
            ctx.auth.session, &data, &ctx.digests);
}

static tool_rc pcrevent(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_success;
    if (!ctx.is_hashsequence_needed) {
        rc = tpm2_pcr_event(ectx, ctx.pcr, ctx.auth.session,
            &ctx.pcrevent_buffer, &ctx.digests, &ctx.cp_hash,
            ctx.parameter_hash_algorithm);
    } else {
        /*
         * Note: We must not calculate pHash in this case to avoid overwriting
         *       the pHash output in the file when we loop.
         */
        rc = pcr_hashsequence(ectx);
    }

    return rc;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

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
    assert(ctx.digests);

    UINT32 i;
    for (i = 0; i < ctx.digests->count; i++) {
        TPMT_HA *d = &ctx.digests->digests[i];

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

    free(ctx.digests);
    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */
    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key handle authorization");
        return rc;
    }
    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    /*
     * If no arguments are given:
     * a. ctx.pcr defaults to zero which is a valid pcr handle
     * b. ctx.input defaults to stdin
     */
    ctx.input = ctx.input ? ctx.input : stdin;
    /*
     * Suppress error reporting with NULL path
     */
    ctx.is_input_not_fifo = files_get_file_size(ctx.input, &ctx.file_size, NULL);
    /*
     * If we can get the non-zero file-size and its less than 1024,
     * just an invocation of TPM2_CC_PCR_EVENT suffices.
     */
    if (ctx.is_input_not_fifo && ctx.file_size &&
    (ctx.file_size <= BUFFER_SIZE(TPM2B_EVENT, buffer))) {
        ctx.pcrevent_buffer.size = ctx.file_size;
        bool result = files_read_bytes(ctx.input, ctx.pcrevent_buffer.buffer,
            ctx.pcrevent_buffer.size);
        if (!result) {
            LOG_ERR("Error reading input file!");
            return tool_rc_general_error;
        }
    } else {
        ctx.is_hashsequence_needed = true;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        0,
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

    return tool_rc_success;
}

static tool_rc check_options(void) {

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
            f = x;
            ctx.input = x;
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
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "auth",   required_argument, NULL, 'P' },
        { "cphash", required_argument, 0,     0  },

    };

    *opts = tpm2_options_new("P:", ARRAY_LEN(topts), topts, on_option, on_arg,
        0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
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
    rc = pcrevent(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */
    return tpm2_session_close(&ctx.auth.session);

    /*
     * 3. Close auxiliary sessions
     */
}

static void tpm2_tool_onexit(void) {

    if (ctx.input && ctx.input != stdin) {
        fclose(ctx.input);
    }
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrevent", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, tpm2_tool_onexit)
