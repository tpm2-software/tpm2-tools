/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "object.h"
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
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } encryption_key;

    TPMI_YES_NO is_decrypt;
    TPM2B_MAX_BUFFER data;
    uint8_t input_data[UINT16_MAX];
    uint16_t input_data_size;
    char *input_path;
    char *out_file_path;
    uint8_t padded_block_len;
    bool is_padding_option_enabled;
    TPMI_ALG_SYM_MODE mode;
    struct {
        char *in;
        char *out;
    } iv;
};

static tpm_encrypt_decrypt_ctx ctx = {
    .mode = TPM2_ALG_NULL,
    .input_data_size = 0,
    .padded_block_len = TPM2_MAX_SYM_BLOCK_SIZE,
    .is_padding_option_enabled = false,
};

static tool_rc readpub(ESYS_CONTEXT *ectx, TPM2B_PUBLIC **public) {

    return tpm2_readpublic(ectx, ctx.encryption_key.object.tr_handle,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      public, NULL, NULL);
}

static tool_rc encrypt_decrypt(ESYS_CONTEXT *ectx, TPM2B_IV *iv_start) {

    tool_rc rc = tool_rc_general_error;

    /*
     * try EncryptDecrypt2 first, and if the command is not supported by the TPM
     * fall back to EncryptDecrypt. Keep track of which version you ran,
     * for error reporting.
     */
    unsigned version = 2;

    UINT16 data_offset = 0;
    bool result = true;
    FILE *out_file_ptr = ctx.out_file_path ? fopen(ctx.out_file_path, "wb+") : stdout;
    if (!out_file_ptr) {
        LOG_ERR("Could not open file \"%s\", error: %s", ctx.out_file_path, strerror(errno));
        return tool_rc_general_error;
    }

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc tmp_rc = tpm2_auth_util_get_shandle(ectx,
                            ctx.encryption_key.object.tr_handle,
                            ctx.encryption_key.object.session, &shandle1);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Failed to get shandle");
        return tmp_rc;
    }

    TPM2B_MAX_BUFFER *out_data = NULL;
    TPM2B_IV *iv_out = NULL;
    TPM2B_IV *iv_in = iv_start;

    unsigned char pad_data[1] = {0};
    unsigned i = 0;

    while (ctx.input_data_size > 0) {
        ctx.data.size =
            ctx.input_data_size > TPM2_MAX_DIGEST_BUFFER ?
                    TPM2_MAX_DIGEST_BUFFER : ctx.input_data_size;

        memcpy(ctx.data.buffer, &ctx.input_data[data_offset], ctx.data.size);

        if (ctx.is_padding_option_enabled && !ctx.is_decrypt &&
            ctx.data.size < TPM2_MAX_DIGEST_BUFFER &&
            (ctx.data.size % ctx.padded_block_len)) {

            pad_data[0] =
                ctx.padded_block_len -(ctx.data.size % ctx.padded_block_len);

            for(i = 0; i < pad_data[0]; i++) {
                ctx.data.buffer[ctx.data.size + i] = pad_data[0];
            }

            ctx.data.size += pad_data[0];
        }

        rc = tpm2_encryptdecrypt(ectx, &ctx.encryption_key.object,
            ctx.is_decrypt, ctx.mode, iv_in,
            &ctx.data, &out_data,
            &iv_out, shandle1, &version);
        if (rc != tool_rc_success) {
            goto out;
        }

        /*
         * Copy iv_out iv_in to use it in next loop iteration.
         * This copy is also output from the tool for further chaining.
         */
        *iv_in = *iv_out;
        free(iv_out);

        result = files_write_bytes(out_file_ptr, out_data->buffer, out_data->size);
        free(out_data);
        if (!result) {
            LOG_ERR("Failed to save output data to file");
            goto out;
        }

        ctx.data.size -= pad_data[0];
        ctx.input_data_size -= ctx.data.size;
        data_offset += ctx.data.size;
    }

    /*
     * iv_in here is the copy of final iv_out from the loop above.
     */
    result = (ctx.iv.out) ?
        files_save_bytes_to_file(ctx.iv.out, iv_in->buffer, iv_in->size) : true;
    if (!result) {
        goto out;
    }

    rc = tool_rc_success;

out:
    if (out_file_ptr != stdout) {
        fclose(out_file_ptr);
    }

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

static bool setup_alg_mode_and_padding(ESYS_CONTEXT *ectx) {

    TPM2B_PUBLIC *public;
    tool_rc rc = readpub(ectx, &public);
    if (rc != tool_rc_success) {
        return false;
    }
    /*
     * Sym objects can have a NULL mode, which means the caller can and must determine mode.
     * Thus if the caller doesn't specify an algorithm, and the object has a default mode, choose it,
     * else choose CFB.
     * If the caller specifies an invalid mode, just pass it to the TPM and let it error out.
     */
    if (ctx.mode == TPM2_ALG_NULL) {

        TPMI_ALG_SYM_MODE objmode = public->publicArea.parameters.symDetail.sym.mode.sym;
        if (objmode == TPM2_ALG_NULL) {
            ctx.mode = TPM2_ALG_CFB;
        } else {
            ctx.mode = objmode;
        }
    }

    if (ctx.is_padding_option_enabled && !ctx.is_decrypt &&
        public->publicArea.parameters.symDetail.sym.algorithm == TPM2_ALG_AES &&
        (ctx.mode == TPM2_ALG_CBC ||
         ctx.mode == TPM2_ALG_ECB ||
         ctx.mode == TPM2_ALG_CFB)) {
        /*
         * https://tools.ietf.org/html/rfc2315 section 10.3 Content-encryption
         * The pkcs#7 requirement of 256 bit max block length for padding
         * applies cleanly since TPM2_MAX_SYM_KEY_BYTES = 32
         */
        ctx.padded_block_len =
            public->publicArea.parameters.symDetail.sym.keyBits.sym/8;
        LOG_WARN("pkcs7 padding is required and has been applied to input data.");
    }

    free(public);

    return true;
}

static bool on_option(char key, char *value) {

    bool result;
    long unsigned int filesize;

    switch (key) {
    case 'c':
        ctx.encryption_key.ctx_path = value;
        break;
    case 'p':
        ctx.encryption_key.auth_str = value;
        break;
    case 'D':
        ctx.is_decrypt = 1;
        break;
    case 'i':
        ctx.input_path = value;
        result = files_get_file_size_path(ctx.input_path, &filesize);
        if (!result) {
            LOG_ERR("Input file size could not be retrieved.");
        }
        if (filesize > UINT16_MAX) {
            LOG_ERR("File size bigger than UINT16_MAX");
        }
        ctx.input_data_size = filesize;
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
    case 'e':
        ctx.is_padding_option_enabled = true;
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
        { "enable-pkcs7-padding", no_argument,       NULL, 'e' },
    };

    *opts = tpm2_options_new("p:eDi:o:c:i:G:t:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.encryption_key.ctx_path) {
        LOG_ERR("Expected a context file or handle, got none.");
        return tool_rc_option_error;
    }

    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
        ctx.input_path, &ctx.input_data_size, ctx.input_data);
    if (!result) {
        return tool_rc_general_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.encryption_key.ctx_path,
        ctx.encryption_key.auth_str, &ctx.encryption_key.object, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid object key authorization, got\"%s\"",
            ctx.encryption_key.auth_str);
        return rc;
    }

    result = setup_alg_mode_and_padding(ectx);
    if (!result) {
        LOG_ERR("Failure to setup key mode and or pkcs7 padding scheme.");
        return tool_rc_general_error;
    }

    TPM2B_IV iv = { .size = sizeof(iv.buffer), .buffer = { 0 } };
    if (ctx.iv.in) {
        unsigned long file_size;
        result = files_get_file_size_path(ctx.iv.in, &file_size);
        if (!result) {
            return tool_rc_general_error;
        }

        if (file_size != iv.size) {
            LOG_ERR("Iv should be 16 bytes, got %lu", file_size);
            return tool_rc_general_error;
        }

        result = files_load_bytes_from_path(ctx.iv.in, iv.buffer, &iv.size);
        if (!result) {
            return tool_rc_general_error;
        }

    }

    if (!ctx.iv.in) {
        LOG_WARN("Using a weak IV, try specifying an IV");
    }

    return encrypt_decrypt(ectx, &iv);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.encryption_key.object.session);
}
