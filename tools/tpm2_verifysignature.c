/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    union {
        struct {
            UINT8 digest :1;
            UINT8 halg :1;
            UINT8 msg :1;
            UINT8 sig :1;
            UINT8 ticket :1;
            UINT8 key_context :1;
            UINT8 fmt;
        };
        UINT8 all;
    } flags;
    TPMI_ALG_SIG_SCHEME format;
    TPMI_ALG_HASH halg;
    TPM2B_DIGEST *msg_hash;
    TPMT_SIGNATURE signature;
    char *msg_file_path;
    char *sig_file_path;
    char *out_file_path;
    const char *context_arg;
    tpm2_loaded_object key_context_object;
};

static tpm2_verifysig_ctx ctx = {
        .format = TPM2_ALG_ERROR,
        .msg_hash = NULL,
        .halg = TPM2_ALG_SHA256
};

static tool_rc verify_signature(ESYS_CONTEXT *context) {

    TPMT_TK_VERIFIED *validation = NULL;

    tool_rc rc = tpm2_verifysignature(context,
            ctx.key_context_object.tr_handle,
            ctx.msg_hash, &ctx.signature, &validation);
    if (rc != tool_rc_success) {
        goto out;
    }

    /*
     * NULL Hierarchies don't produce validation data, so let the user know
     * by issuing a warning.
     */
    if (ctx.out_file_path) {
        if (validation->hierarchy == TPM2_RH_NULL) {
            LOG_WARN("The NULL hierarchy doesn't produce a validation ticket,"
                    " not outputting ticket");
        } else {
            if (!files_save_ticket(validation, ctx.out_file_path)) {
                rc = tool_rc_general_error;
            }
        }
    }
out:
    free(validation);
    return rc;
}

static TPM2B *message_from_file(const char *msg_file_path) {

    unsigned long size;

    bool result = files_get_file_size_path(msg_file_path, &size);
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
    if (!files_load_bytes_from_path(msg_file_path, msg->buffer, &tmp)) {
        free(msg);
        return NULL;
    }
    return msg;
}

static tool_rc init(ESYS_CONTEXT *context) {

    tool_rc rc = tool_rc_general_error;

    /* check flags for mismatches */
    if (ctx.flags.digest && (ctx.flags.msg || ctx.flags.halg)) {
        LOG_ERR("Cannot specify --digest (-d) and ( --msg (-m) or --halg (-g) )");
        return tool_rc_option_error;
    }

    if (!(ctx.context_arg && ctx.flags.sig)) {
        LOG_ERR("--key-context (-c) and --sig (-s) are required");
        return tool_rc_option_error;
    }

    TPM2B *msg = NULL;

    tool_rc tmp_rc = tpm2_util_object_load(context, ctx.context_arg,
            &ctx.key_context_object, TPM2_HANDLE_ALL_W_NV);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }

    if (ctx.flags.msg) {
        msg = message_from_file(ctx.msg_file_path);

        if (!msg) {
            /* message_from_file() logs specific error no need to here */
            return tool_rc_general_error;
        }
    }

    if (ctx.flags.sig) {

        tpm2_convert_sig_fmt fmt =
                ctx.flags.fmt ? signature_format_plain : signature_format_tss;
        bool res = tpm2_convert_sig_load(ctx.sig_file_path, fmt, ctx.format,
                ctx.halg, &ctx.signature);
        if (!res) {
            goto err;
        }
    }

    /* If no digest is specified, compute it */
    if (!ctx.flags.digest) {
        if (!msg) {
            /*
             * This is a redundant check since main() checks this case, but
             * we'll add it here to silence any complainers (such as static
             * analysers).
             */
            LOG_ERR("No digest set and no message file to compute from, cannot "
                    "compute message hash!");
            goto err;
        }

        tmp_rc = tpm2_hash_compute_data(context, ctx.halg, TPM2_RH_NULL,
                msg->buffer, msg->size, &ctx.msg_hash, NULL);
        if (tmp_rc != tool_rc_success) {
            rc = tmp_rc;
            LOG_ERR("Compute message hash failed!");
            goto err;
        }
    }

    rc = tool_rc_success;

err:
    free(msg);
    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'g': {
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Unable to convert algorithm, got: \"%s\"", value);
            return false;
        }
        ctx.flags.halg = 1;
    }
        break;
    case 'm': {
        ctx.msg_file_path = value;
        ctx.flags.msg = 1;
    }
        break;
    case 'd': {
        ctx.msg_hash = malloc(sizeof(TPM2B_DIGEST));
        ctx.msg_hash->size = sizeof(ctx.msg_hash->buffer);
        if (!files_load_bytes_from_path(value, ctx.msg_hash->buffer,
                &ctx.msg_hash->size)) {
            LOG_ERR("Could not load digest from file!");
            return false;
        }
        ctx.flags.digest = 1;
    }
        break;
    case 0:
	LOG_WARN("Option \"--format\" is deprecated, use \"--scheme\"");
        /* falls through */
    case 'f':
        ctx.format = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
        if (ctx.format == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }

        ctx.flags.fmt = 1;
        break;
    case 's':
        ctx.sig_file_path = value;
        ctx.flags.sig = 1;
        break;
    case 't':
        ctx.out_file_path = value;
        ctx.flags.ticket = 1;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
            { "digest",         required_argument, NULL, 'd' },
            { "hash-algorithm", required_argument, NULL, 'g' },
            { "message",        required_argument, NULL, 'm' },
            { "format",         required_argument, NULL,  0  },
            { "scheme",         required_argument, NULL, 'f' },
            { "signature",      required_argument, NULL, 's' },
            { "ticket",         required_argument, NULL, 't' },
            { "key-context",    required_argument, NULL, 'c' },
    };


    *opts = tpm2_options_new("g:m:d:f:s:t:c:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    /* initialize and process */
    tool_rc rc = init(context);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = verify_signature(context);
    if (rc != tool_rc_success) {
        LOG_ERR("Verify signature failed!");
        return rc;
    }

    return tool_rc_success;
}

static void tpm2_tool_onexit(void) {
    if (ctx.msg_hash) {
        free(ctx.msg_hash);
    }
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("verifysignature", tpm2_tool_onstart, tpm2_tool_onrun, NULL, tpm2_tool_onexit)
