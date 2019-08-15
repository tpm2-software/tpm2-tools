/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
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
};

static tpm_sign_ctx ctx = {
        .halg = TPM2_ALG_SHA1,
        .sig_scheme = TPM2_ALG_NULL
};

static tool_rc sign_and_save(ESYS_CONTEXT *ectx) {

    TPMT_SIGNATURE *signature;
    bool result;

    tool_rc rc = tpm2_sign(ectx, &ctx.signing_key.object, ctx.digest,
            &ctx.in_scheme, &ctx.validation, &signature);
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

    bool option_fail = false;

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Expected option c");
        option_fail = true;
    }

    if (!ctx.flags.o) {
        LOG_ERR("Expected option o");
        option_fail = true;
    }

    if (option_fail) {
        return tool_rc_option_error;
    }

    if (ctx.flags.d && ctx.flags.t) {
        LOG_WARN("When using a pre-computed digest the validation ticket"
                " is ignored.");
    }

    if (ctx.flags.d || !ctx.flags.t) {
        ctx.validation.tag = TPM2_ST_HASHCHECK;
        ctx.validation.hierarchy = TPM2_RH_NULL;
        memset(&ctx.validation.digest, 0, sizeof(ctx.validation.digest));
    }

    /*
     * Set signature scheme for key type, or validate chosen scheme is allowed for key type.
     */
    tool_rc rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.signing_key.object.tr_handle, ctx.halg, ctx.sig_scheme,
            &ctx.in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("bad signature scheme for key type!");
        return rc;
    }

    /* Process the msg file if needed */
    if (!ctx.flags.d) {
        FILE *input = ctx.input_file ? fopen(ctx.input_file, "rb") : stdin;
        if (!input) {
            LOG_ERR("Could not open file \"%s\"", ctx.input_file);
            return tool_rc_general_error;
        }

        rc = tpm2_hash_file(ectx, ctx.halg, TPM2_RH_NULL, input, &ctx.digest,
                NULL);
        if (input != stdin) {
            fclose(input);
        }
        if (rc != tool_rc_success) {
            LOG_ERR("Could not hash input");
        }
        return rc;
        /* we don't need to perform the digest, just read it */
    }

    /* else process it as a pre-computed digest */
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

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth",                 required_argument, NULL, 'p' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "scheme",               required_argument, NULL, 's' },
      { "digest",               no_argument,       NULL, 'd' },
      { "signature",            required_argument, NULL, 'o' },
      { "ticket",               required_argument, NULL, 't' },
      { "key-context",          required_argument, NULL, 'c' },
      { "format",               required_argument, NULL, 'f' }
    };

    *opts = tpm2_options_new("p:g:dt:o:c:f:s:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

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

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.signing_key.object.session);
}

void tpm2_tool_onexit(void) {

    if (ctx.digest) {
        free(ctx.digest);
    }
    free(ctx.msg);
}
