/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"

typedef struct tpm_rsaencrypt_ctx tpm_rsaencrypt_ctx;
struct tpm_rsaencrypt_ctx {
    const char *context_arg;
    tpm2_loaded_object key_context;
    TPM2B_PUBLIC_KEY_RSA message;
    char *output_path;
    char *input_path;
    TPMT_RSA_DECRYPT scheme;
};

static tpm_rsaencrypt_ctx ctx = {
    .context_arg = NULL,
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static tool_rc rsa_encrypt_and_save(ESYS_CONTEXT *context) {

    bool ret = true;
    // Inputs
    TPM2B_DATA label;
    // Outputs
    TPM2B_PUBLIC_KEY_RSA *out_data;

    label.size = 0;

    TSS2_RC rval = Esys_RSA_Encrypt(context, ctx.key_context.tr_handle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &ctx.message, &ctx.scheme, &label, &out_data);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_RSA_Encrypt, rval);
        return tool_rc_from_tpm(rval);
    }

    if (ctx.output_path) {
        ret = files_save_bytes_to_file(ctx.output_path, out_data->buffer,
                out_data->size);
    }

    tpm2_util_print_tpm2b((TPM2B *)out_data);

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
    case 'g':
        ctx.scheme.scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_rsa_scheme);
        if (ctx.scheme.scheme == TPM2_ALG_ERROR) {
            return false;
        }
        break;
    }
    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one hash input file, got: %d", argc);
        return false;
    }

    ctx.input_path = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      {"out-file",    required_argument, NULL, 'o'},
      {"key-context", required_argument, NULL, 'c'},
      {"scheme",      required_argument, NULL, 'g'},
    };

    *opts = tpm2_options_new("o:c:g:", ARRAY_LEN(topts), topts,
                             on_option, on_args, 0);

    return *opts != NULL;
}

static bool init(ESYS_CONTEXT *context) {

    if (!ctx.context_arg) {
        LOG_ERR("Expected option C");
        return false;
    }

    bool result = tpm2_util_object_load(context,
                                ctx.context_arg, &ctx.key_context);
    if (!result) {
        return false;
    }

    ctx.message.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    return files_load_bytes_from_buffer_or_file_or_stdin(NULL,ctx.input_path,
        &ctx.message.size, ctx.message.buffer);
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = init(context);
    if (!result) {
        return tool_rc_general_error;
    }

    return rsa_encrypt_and_save(context);
}
