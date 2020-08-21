/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"

typedef struct tpm_sign_ctx tpm_sign_ctx;
struct tpm_sign_ctx {
    TPMT_TK_HASHCHECK validation;
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    TPMT_SIG_SCHEME in_scheme;
    TPM2B_DIGEST *digest;
    char *output_path;
    BYTE *msg;
    UINT16 length;
    char *input_file;
    tpm2_convert_sig_fmt sig_format;

    struct {
        UINT8 d :1;
        UINT8 t :1;
        UINT8 o :1;
    } flags;

    char *cp_hash_path;
    char *commit_index;
};

static tpm_sign_ctx ctx = {
        .halg = TPM2_ALG_NULL,
        .sig_scheme = TPM2_ALG_NULL
};

static tool_rc sign_and_save(ESYS_CONTEXT *ectx) {

    TPMT_SIGNATURE *signature;
    bool result;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_sign(ectx, &ctx.signing_key.object, ctx.digest,
            &ctx.in_scheme, &ctx.validation, &signature, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }

        return rc;
    }

    tool_rc rc = tpm2_sign(ectx, &ctx.signing_key.object, ctx.digest,
            &ctx.in_scheme, &ctx.validation, &signature, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    result = tpm2_convert_sig_save(signature, ctx.sig_format, ctx.output_path);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    rc = tool_rc_success;

out:
    free(signature);

    return rc;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    /*
     * Set signature scheme for key type, or validate chosen scheme is
     * allowed for key type.
     */
    tool_rc rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme,
            &ctx.in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid signature scheme for key type!");
        return rc;
    }

    if (ctx.in_scheme.scheme != TPM2_ALG_ECDAA && ctx.commit_index) {
        LOG_ERR("Commit counter is only applicable in an ECDAA scheme.");
        return tool_rc_option_error;
    }

    if (ctx.in_scheme.scheme == TPM2_ALG_ECDAA && ctx.commit_index) {
        bool result = tpm2_util_string_to_uint16(ctx.commit_index,
            &ctx.in_scheme.details.ecdaa.count);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    if (ctx.in_scheme.scheme == TPM2_ALG_ECDAA &&
    ctx.sig_format != signature_format_tss) {
        LOG_ERR("Only TSS signature format is possible with ECDAA scheme");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && ctx.output_path) {
        LOG_ERR("Cannot output signature when calculating cpHash");
        return tool_rc_option_error;
    }

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Expected option c");
        return tool_rc_option_error;
    }

    if (!ctx.flags.o && !ctx.cp_hash_path) {
        LOG_ERR("Expected option o");
        return tool_rc_option_error;
    }

    if (!ctx.flags.d && ctx.flags.t) {
        LOG_WARN("Ignoring the specified validation ticket since no TPM "
                 "calculated digest specified.");
    }

    /*
     * Applicable when input data is not a digest, rather the message to sign.
     * A digest is calculated first in this case.
     */
    if (!ctx.flags.d) {
        FILE *input = ctx.input_file ? fopen(ctx.input_file, "rb") : stdin;
        if (!input) {
            LOG_ERR("Could not open file \"%s\"", ctx.input_file);
            return tool_rc_general_error;
        }

        TPMT_TK_HASHCHECK *temp_validation_ticket;
        rc = tpm2_hash_file(ectx, ctx.halg, TPM2_RH_OWNER, input, &ctx.digest,
                &temp_validation_ticket);
        if (input != stdin) {
            fclose(input);
        }
        if (rc != tool_rc_success) {
            LOG_ERR("Could not hash input");
        }

        ctx.validation = *temp_validation_ticket;
        free(temp_validation_ticket);

        /*
         * we don't need to perform the digest, just read it
         */
        return rc;
    }

    /*
     * else process it as a pre-computed digest
     */
    ctx.digest = malloc(sizeof(TPM2B_DIGEST));
    if (!ctx.digest) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    ctx.digest->size = sizeof(ctx.digest->buffer);
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.input_file, &ctx.digest->size, ctx.digest->buffer);
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * Applicable to un-restricted signing keys
     * NOTE: When digests without tickets are specified for restricted keys,
     * the sign operation will fail.
     */
    if (ctx.flags.d && !ctx.flags.t) {
        ctx.validation.tag = TPM2_ST_HASHCHECK;
        ctx.validation.hierarchy = TPM2_RH_NULL;
        memset(&ctx.validation.digest, 0, sizeof(ctx.validation.digest));
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.signing_key.ctx_path = value;
        break;
    case 'p':
        ctx.signing_key.auth_str = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert to number or lookup algorithm, got: "
                    "\"%s\"", value);
            return false;
        }
        break;
    case 's': {
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
    }
        break;
    case 'd':
        ctx.flags.d = 1;
        break;
    case 't': {
        bool result = files_load_validation(value, &ctx.validation);
        if (!result) {
            return false;
        }
        ctx.flags.t = 1;
    }
        break;
    case 'o':
        ctx.output_path = value;
        ctx.flags.o = 1;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.commit_index = value;
        break;
    case 'f':
        ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
        /* no default */
    }

    return true;
}

static bool on_args(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected one input file, got: %d", argc);
        return false;
    }

    ctx.input_file = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth",                 required_argument, NULL, 'p' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "scheme",               required_argument, NULL, 's' },
      { "digest",               no_argument,       NULL, 'd' },
      { "signature",            required_argument, NULL, 'o' },
      { "ticket",               required_argument, NULL, 't' },
      { "key-context",          required_argument, NULL, 'c' },
      { "format",               required_argument, NULL, 'f' },
      { "cphash",               required_argument, NULL,  0  },
      { "commit-index",       required_argument, NULL,  1  },
    };

    *opts = tpm2_options_new("p:g:dt:o:c:f:s:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
            ctx.signing_key.auth_str, &ctx.signing_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return sign_and_save(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.signing_key.object.session);
}

static void tpm2_tool_onexit(void) {

    if (ctx.digest) {
        free(ctx.digest);
    }
    free(ctx.msg);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("sign", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, tpm2_tool_onexit)
