/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"

typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    struct {
        UINT8 i : 1;
        UINT8 o : 1;
    } flags;
    struct {
        char *auth_str;
        tpm2_session *session;
        const char *context_arg;
        tpm2_loaded_object object;
    } key;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *output_file_path;
    TPMT_RSA_DECRYPT scheme;
};

tpm_rsadecrypt_ctx ctx = {
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static bool rsa_decrypt_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA *message;

    label.size = 0;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.key.object.tr_handle,
                            ctx.key.session);
    if (shandle1 == ESYS_TR_NONE) {
        return false;
    }

    TSS2_RC rval = Esys_RSA_Decrypt(ectx, ctx.key.object.tr_handle,
                        shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                        &ctx.cipher_text, &ctx.scheme, &label, &message);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_RSA_Decrypt, rval);
        return false;
    }

    bool ret = files_save_bytes_to_file(ctx.output_file_path, message->buffer,
                    message->size);

    free(message);

    return ret;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.context_arg = value;
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
      { "auth-key",     required_argument, NULL, 'p' },
      { "in-file",      required_argument, NULL, 'i' },
      { "out-file",     required_argument, NULL, 'o' },
      { "key-context",  required_argument, NULL, 'c' },
      { "scheme",       required_argument, NULL, 'g' },
    };

    *opts = tpm2_options_new("p:i:o:c:g:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static bool init(ESYS_CONTEXT *ectx) {


    if (!(ctx.key.context_arg && ctx.flags.i && ctx.flags.o)) {
        LOG_ERR("Expected arguments i, o and c.");
        return false;
    }

    return tpm2_util_object_load(ectx, ctx.key.context_arg,
                                &ctx.key.object);
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init(ectx);
    if (!result) {
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.key.auth_str,
            &ctx.key.session, false);
    if (!result) {
        LOG_ERR("Invalid key authorization, got\"%s\"", ctx.key.auth_str);
        goto out;
    }

    result = rsa_decrypt_and_save(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_session_close(&ctx.key.session);
    if (!result) {
        rc = 1;
    }

    return rc;
}
