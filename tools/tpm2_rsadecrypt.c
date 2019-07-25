/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    struct {
        UINT8 i : 1;
        UINT8 o : 1;
    } flags;

    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *output_file_path;
    TPMT_RSA_DECRYPT scheme;
};

tpm_rsadecrypt_ctx ctx = {
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static tool_rc rsa_decrypt_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA *message;

    label.size = 0;

    tool_rc rc = tpm2_rsa_decrypt(
                    ectx,
                    &ctx.key.object,
                    &ctx.cipher_text,
                    &ctx.scheme,
                    &label,
                    &message);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool ret = files_save_bytes_to_file(ctx.output_file_path, message->buffer,
                    message->size);

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
    case 'i': {
        ctx.cipher_text.size = sizeof(ctx.cipher_text) - 2;
        bool result = files_load_bytes_from_path(value, ctx.cipher_text.buffer,
                &ctx.cipher_text.size);
        if (!result) {
            return false;
        }
        ctx.flags.i = 1;
    }
        break;
    case 'o': {
        ctx.output_file_path = value;
        ctx.flags.o = 1;
        break;
    }
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

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "auth",         required_argument, NULL, 'p' },
      { "input",        required_argument, NULL, 'i' },
      { "output",       required_argument, NULL, 'o' },
      { "key-context",  required_argument, NULL, 'c' },
      { "scheme",       required_argument, NULL, 'g' },
    };

    *opts = tpm2_options_new("p:i:o:c:g:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *ectx) {


    if (!(ctx.key.ctx_path && ctx.flags.i && ctx.flags.o)) {
        LOG_ERR("Expected arguments i, o and c.");
        return tool_rc_option_error;
    }

    return tpm2_util_object_load_auth(ectx, ctx.key.ctx_path, ctx.key.auth_str,
                                &ctx.key.object, false, TPM2_HANDLES_ALL_W_NV);
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return rsa_decrypt_and_save(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.key.object.session);
}
