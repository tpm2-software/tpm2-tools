/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_encrypt_decrypt_ctx tpm_encrypt_decrypt_ctx;
struct tpm_encrypt_decrypt_ctx {
    struct {
        tpm2_session *session;
        char *auth_str;
        const char *context_arg;
        tpm2_loaded_object context;
    } object;

    TPMI_YES_NO is_decrypt;
    TPM2B_MAX_BUFFER data;
    char *input_path;
    char *out_file_path;
    TPMI_ALG_SYM_MODE mode;
    struct {
        char *in;
        char *out;
    } iv;
    struct {
        UINT8 D : 1;
        UINT8 i : 1;
        UINT8 X : 1;
    } flags;
};

static tpm_encrypt_decrypt_ctx ctx = {
    .mode = TPM2_ALG_NULL,
};

static tool_rc readpub(ESYS_CONTEXT *ectx, TPM2B_PUBLIC **public) {

    return tpm2_readpublic(ectx, ctx.object.context.tr_handle,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      public, NULL, NULL);
}

static tool_rc encrypt_decrypt(ESYS_CONTEXT *ectx, TPM2B_IV *iv_in) {

    tool_rc rc = tool_rc_general_error;

    TPM2B_MAX_BUFFER *out_data;
    TPM2B_IV *iv_out;

    /*
     * try EncryptDecrypt2 first, and if the command is not supported by the TPM
     * fall back to EncryptDecrypt. Keep track of which version you ran,
     * for error reporting.
     */
    unsigned version = 2;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.object.context.tr_handle,
                            ctx.object.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return tool_rc_general_error;
    }

    TSS2_RC rval = Esys_EncryptDecrypt2(ectx, ctx.object.context.tr_handle,
                      shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                      &ctx.data, ctx.is_decrypt, ctx.mode, iv_in,
                      &out_data, &iv_out);
    if (tpm2_error_get(rval) == TPM2_RC_COMMAND_CODE) {
        version = 1;
        rval = Esys_EncryptDecrypt(ectx, ctx.object.context.tr_handle,
                  shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                  ctx.is_decrypt, ctx.mode, iv_in, &ctx.data,
                  &out_data, &iv_out);
    }
    if (rval != TPM2_RC_SUCCESS) {
        if (version == 2) {
            LOG_PERR(Esys_EncryptDecrypt2, rval);
        } else {
            LOG_PERR(Esys_EncryptDecrypt, rval);
        }
        return tool_rc_from_tpm(rval);
    }

    bool result = files_save_bytes_to_file(ctx.out_file_path, out_data->buffer,
            out_data->size);
    if (!result) {
        goto out;
    }

    result = ctx.iv.out ? files_save_bytes_to_file(ctx.iv.out,
                                iv_out->buffer,
                                iv_out->size) : true;
    if (!result) {
        goto out;
    }

    rc = tool_rc_success;

out:
    free(out_data);
    free(iv_out);

    return rc;
}

static void parse_iv(char *value) {

    ctx.iv.in = value;

    char *split = strchr(value, ':');
    if (split) {
        *split = '\0';
        split++;
        if (split) {
            ctx.iv.out = split;
        }
    }
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.object.context_arg = value;
        break;
    case 'p':
        ctx.object.auth_str = value;
        break;
    case 'D':
        ctx.is_decrypt = 1;
        break;
    case 'i':
        ctx.input_path = value;
        ctx.flags.i = 1;
        break;
    case 'o':
        ctx.out_file_path = value;
        break;
    case 'G':
        ctx.mode = tpm2_alg_util_strtoalg(value, tpm2_alg_util_flags_mode);
        if (ctx.mode == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid mode, got: %s", value);
            return false;
        }
        break;
    case 't':
        parse_iv(value);
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-key",             required_argument, NULL, 'p' },
        { "decrypt",              no_argument,       NULL, 'D' },
        { "in-file",              required_argument, NULL, 'i' },
        { "iv",                   required_argument, NULL, 't' },
        { "mode",                 required_argument, NULL, 'G' },
        { "out-file",             required_argument, NULL, 'o' },
        { "key-context",          required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("p:Di:o:c:i:G:t:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result;
    tool_rc rc = tool_rc_general_error;

    if (!ctx.object.context_arg) {
        LOG_ERR("Expected a context file or handle, got none.");
        return tool_rc_option_error;
    }

    ctx.data.size = sizeof(ctx.data.buffer);
    result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,ctx.input_path,
        &ctx.data.size, ctx.data.buffer);
    if (!result) {
        return rc;
    }

    result = tpm2_util_object_load(ectx, ctx.object.context_arg,
                                &ctx.object.context);
    if (!result) {
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.object.auth_str,
            &ctx.object.session, false);
    if (!result) {
        LOG_ERR("Invalid object key authorization, got\"%s\"",
            ctx.object.auth_str);
        goto out;
    }

    /*
     * Sym objects can have a NULL mode, which means the caller can and must determine mode.
     * Thus if the caller doesn't specify an algorithm, and the object has a default mode, choose it,
     * else choose CFB.
     * If the caller specifies an invalid mode, just pass it to the TPM and let it error out.
     */
    if (ctx.mode == TPM2_ALG_NULL) {

        TPM2B_PUBLIC *public;
        rc = readpub(ectx, &public);
        if (rc != tool_rc_success) {
            goto out;
        }

        TPMI_ALG_SYM_MODE objmode = public->publicArea.parameters.symDetail.sym.mode.sym;
        if (objmode == TPM2_ALG_NULL) {
            ctx.mode = TPM2_ALG_CFB;
        } else {
            ctx.mode = objmode;
        }

        free(public);
    }

    TPM2B_IV iv = { .size = sizeof(iv.buffer), .buffer = { 0 } };
    if (ctx.iv.in) {
        unsigned long file_size;
        result = files_get_file_size_path(ctx.iv.in, &file_size);
        if (!result) {
            goto out;
        }

        if (file_size != iv.size) {
            LOG_ERR("Iv should be 16 bytes, got %lu", file_size);
            goto out;
        }

        result = files_load_bytes_from_path(ctx.iv.in, iv.buffer, &iv.size);
        if (!result) {
            goto out;
        }

    }

    if (!ctx.iv.in) {
        LOG_WARN("Using a weak IV, try specifying an IV");
    }

    rc = encrypt_decrypt(ectx, &iv);

out:
    result = tpm2_session_close(&ctx.object.session);
    if (!result) {
        rc = tool_rc_general_error;
    }

    return rc;
}
