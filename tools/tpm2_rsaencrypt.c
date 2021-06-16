/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_rsaencrypt_ctx tpm_rsaencrypt_ctx;
struct tpm_rsaencrypt_ctx {
    const char *context_arg;
    tpm2_loaded_object key_context;
    TPM2B_PUBLIC_KEY_RSA message;
    char *output_path;
    char *input_path;
    TPMT_RSA_DECRYPT scheme;
    const char *scheme_str;
    TPM2B_DATA label;
};

static tpm_rsaencrypt_ctx ctx = {
    .context_arg = NULL,
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static tool_rc rsa_encrypt_and_save(ESYS_CONTEXT *context) {

    bool ret = false;
    TPM2B_PUBLIC_KEY_RSA *out_data = NULL;

    tool_rc rc = tpm2_rsa_encrypt(context, &ctx.key_context,
            &ctx.message, &ctx.scheme, &ctx.label, &out_data);
    if (rc != tool_rc_success) {
        return rc;
    }

    FILE *f = ctx.output_path ? fopen(ctx.output_path, "wb+") : stdout;
    if (!f) {
        goto out;
    }

    ret = files_write_bytes(f, out_data->buffer, out_data->size);
    if (f != stdout) {
        fclose(f);
    }

out:
    free(out_data);
    return ret ? tool_rc_success : tool_rc_general_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'o':
        ctx.output_path = value;
        break;
    case 's':
        ctx.scheme_str = value;
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

    static const struct option topts[] = {
      {"output",      required_argument, NULL, 'o'},
      {"key-context", required_argument, NULL, 'c'},
      {"scheme",      required_argument, NULL, 's'},
      {"label",       required_argument, NULL, 'l'},
    };

    *opts = tpm2_options_new("o:c:s:l:", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *context) {

    if (!ctx.context_arg) {
        LOG_ERR("Expected option c");
        return tool_rc_option_error;
    }

    ctx.message.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.input_path, &ctx.message.size, ctx.message.buffer);
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * Load the decryption key
     */
    tool_rc rc = tpm2_util_object_load(context, ctx.context_arg, &ctx.key_context,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPM2B_PUBLIC *key_public_info = 0;
    rc = tpm2_readpublic(context, ctx.key_context.tr_handle, &key_public_info,
        NULL, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    if (key_public_info->publicArea.type != TPM2_ALG_RSA) {
            LOG_ERR("Unsupported key type for RSA decryption.");
            rc = tool_rc_general_error;
            goto out;
    }

    /*
     * Get scheme information
     */
    if (ctx.scheme_str) {
        rc = tpm2_alg_util_handle_rsa_ext_alg(ctx.scheme_str, key_public_info);
        ctx.scheme.scheme =
            key_public_info->publicArea.parameters.rsaDetail.scheme.scheme;
        ctx.scheme.details.anySig.hashAlg =
            key_public_info->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg;
    }

out:
    Esys_Free(key_public_info);

    return rc;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(context);
    if (rc != tool_rc_success) {
        return rc;
    }

    return rsa_encrypt_and_save(context);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("rsaencrypt", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
