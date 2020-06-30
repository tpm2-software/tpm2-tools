/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *input_path;
    char *output_file_path;
    TPMT_RSA_DECRYPT scheme;

    char *cp_hash_path;
};

static tpm_rsadecrypt_ctx ctx = {
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static tool_rc rsa_decrypt_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_PUBLIC_KEY_RSA *message = NULL;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_rsa_decrypt(ectx, &ctx.key.object, &ctx.cipher_text,
            &ctx.scheme, &ctx.label, &message, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }

        return rc;
    }

    tool_rc rc = tpm2_rsa_decrypt(ectx, &ctx.key.object, &ctx.cipher_text,
            &ctx.scheme, &ctx.label, &message, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool ret = false;
    FILE *f =
            ctx.output_file_path ? fopen(ctx.output_file_path, "wb+") : stdout;
    if (!f) {
        goto out;
    }

    ret = files_write_bytes(f, message->buffer, message->size);
    if (f != stdout) {
        fclose(f);
    }

out:
    free(message);

    return ret ? tool_rc_success : tool_rc_general_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
        break;
    case 'o': {
        ctx.output_file_path = value;
        break;
    }
    case 's':
        ctx.scheme.scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_rsa_scheme);
        if (ctx.scheme.scheme == TPM2_ALG_ERROR) {
            return false;
        }
        ctx.scheme.details.oaep.hashAlg = ctx.scheme.scheme == TPM2_ALG_OAEP ?
            TPM2_ALG_SHA256 : 0;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 'l':
        return tpm2_util_get_label(value, &ctx.label);
    }
    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one input file, got: %d", argc);
        return false;
    }

    ctx.input_path = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "auth",        required_argument, NULL, 'p' },
      { "output",      required_argument, NULL, 'o' },
      { "key-context", required_argument, NULL, 'c' },
      { "scheme",      required_argument, NULL, 's' },
      { "label",       required_argument, NULL, 'l' },
      { "cphash",      required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("p:o:c:s:l:", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    if (!ctx.key.ctx_path) {
        LOG_ERR("Expected argument -c.");
        return tool_rc_option_error;
    }

    if (ctx.output_file_path && ctx.cp_hash_path) {
        LOG_ERR("Cannout decrypt when calculating cphash");
        return tool_rc_option_error;
    }

    ctx.cipher_text.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.input_path, &ctx.cipher_text.size, ctx.cipher_text.buffer);
    if (!result) {
        return tool_rc_general_error;
    }

    return tpm2_util_object_load_auth(ectx, ctx.key.ctx_path, ctx.key.auth_str,
            &ctx.key.object, false, TPM2_HANDLE_ALL_W_NV);
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return rsa_decrypt_and_save(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.key.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("rsadecrypt", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
