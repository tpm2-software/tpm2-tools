/* SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

#define MAX_INPUT_DATA_SIZE UINT16_MAX

typedef struct tpm_encrypt_decrypt_ctx tpm_encrypt_decrypt_ctx;
struct tpm_encrypt_decrypt_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } encryption_key;

    TPMI_YES_NO is_decrypt;

    uint8_t input_data[MAX_INPUT_DATA_SIZE];
    uint16_t input_data_size;

    const char *input_path;
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
    .input_data_size = MAX_INPUT_DATA_SIZE,
    .padded_block_len = TPM2_MAX_SYM_BLOCK_SIZE,
    .is_padding_option_enabled = false,
};

static tool_rc readpub(ESYS_CONTEXT *ectx, TPM2B_PUBLIC **public) {

    return tpm2_readpublic(ectx, ctx.encryption_key.object.tr_handle,
            public, NULL, NULL);
}

static bool evaluate_pkcs7_padding_requirements(uint16_t remaining_bytes,
bool expected) {

    if (!ctx.is_padding_option_enabled) {
        return false;
    }

    if (ctx.is_decrypt != expected) {
        return false;
    }

    /*
     * If no ctx.mode was specified, the default cfb was set.
     */
    if (ctx.mode != TPM2_ALG_CBC && ctx.mode != TPM2_ALG_ECB) {
        return false;
    }

    /*
     * Is last block?
     */
    if (!(remaining_bytes <= TPM2_MAX_DIGEST_BUFFER && remaining_bytes > 0)) {
        return false;
    }

    LOG_WARN("Processing pkcs7 padding.");

    return true;
}

static void append_pkcs7_padding_data_to_input(uint8_t *pad_data,
        uint16_t *in_data_size, uint16_t *remaining_bytes) {

    bool test_pad_reqs = evaluate_pkcs7_padding_requirements(*remaining_bytes,
    false);
    if (!test_pad_reqs) {
        return;
    }

    *pad_data = ctx.padded_block_len - (*in_data_size % ctx.padded_block_len);

    memset(&ctx.input_data[ctx.input_data_size], *pad_data, *pad_data);

    if (*pad_data == ctx.padded_block_len) {
        *remaining_bytes += *pad_data;
    }

    if (*pad_data < ctx.padded_block_len) {
        *remaining_bytes = *in_data_size += *pad_data;
    }
}

static void strip_pkcs7_padding_data_from_output(uint8_t *pad_data,
        TPM2B_MAX_BUFFER *out_data, uint16_t *remaining_bytes) {

    bool test_pad_reqs = evaluate_pkcs7_padding_requirements(*remaining_bytes,
    true);
    if (!test_pad_reqs) {
        return;
    }

    uint8_t last_block_length = ctx.padded_block_len
            - (out_data->size % ctx.padded_block_len);

    if (last_block_length != ctx.padded_block_len) {
        LOG_WARN("Encrypted input is not block length aligned.");
    }

    *pad_data = out_data->buffer[last_block_length - 1];

    out_data->size -= *pad_data;
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
    FILE *out_file_ptr =
            ctx.out_file_path ? fopen(ctx.out_file_path, "wb+") : stdout;
    if (!out_file_ptr) {
        LOG_ERR("Could not open file \"%s\", error: %s", ctx.out_file_path,
                strerror(errno));
        return tool_rc_general_error;
    }

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc tmp_rc = tpm2_auth_util_get_shandle(ectx,
            ctx.encryption_key.object.tr_handle,
            ctx.encryption_key.object.session, &shandle1);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        LOG_ERR("Failed to get shandle");
        goto out;
    }

    TPM2B_MAX_BUFFER *out_data = NULL;
    TPM2B_MAX_BUFFER in_data;
    TPM2B_IV *iv_out = NULL;
    TPM2B_IV *iv_in = iv_start;
    uint8_t pad_data = 0;

    uint16_t remaining_bytes = ctx.input_data_size;
    if (ctx.mode == TPM2_ALG_ECB) {
        iv_in = NULL;
    }
    while (remaining_bytes > 0) {
        in_data.size =
                remaining_bytes > TPM2_MAX_DIGEST_BUFFER ?
                        TPM2_MAX_DIGEST_BUFFER : remaining_bytes;

        if (!pad_data) {
            append_pkcs7_padding_data_to_input(&pad_data, &in_data.size,
                    &remaining_bytes);
        }

        memcpy(in_data.buffer, &ctx.input_data[data_offset], in_data.size);

        rc = tpm2_encryptdecrypt(ectx, &ctx.encryption_key.object,
                ctx.is_decrypt, ctx.mode, iv_in, &in_data, &out_data, &iv_out,
                shandle1, &version);
        if (rc != tool_rc_success) {
            goto out;
        }

        /*
         * Copy iv_out iv_in to use it in next loop iteration.
         * This copy is also output from the tool for further chaining.
         */
        if (ctx.mode != TPM2_ALG_ECB) {
            assert(iv_in);
            assert(iv_out);
            *iv_in = *iv_out;
            free(iv_out);
        }

        strip_pkcs7_padding_data_from_output(&pad_data, out_data,
                &remaining_bytes);

        result = files_write_bytes(out_file_ptr, out_data->buffer,
                out_data->size);
        free(out_data);
        if (!result) {
            LOG_ERR("Failed to save output data to file");
            goto out;
        }

        remaining_bytes -= in_data.size;
        data_offset += in_data.size;
    }

    /*
     * iv_in here is the copy of final iv_out from the loop above.
     */
    result =
            (ctx.iv.out && iv_in) ?
                    files_save_bytes_to_file(ctx.iv.out, iv_in->buffer,
                            iv_in->size) :
                    true;
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

static bool setup_alg_mode_and_iv_and_padding(ESYS_CONTEXT *ectx, TPM2B_IV *iv) {

    bool result;
    if (ctx.iv.in) {
        unsigned long file_size;
        result = files_get_file_size_path(ctx.iv.in, &file_size);
        if (!result) {
            return tool_rc_general_error;
        }

        if (file_size != iv->size) {
            LOG_ERR("Iv should be 16 bytes, got %lu", file_size);
            return tool_rc_general_error;
        }

        result = files_load_bytes_from_path(ctx.iv.in, iv->buffer, &iv->size);
        if (!result) {
            return tool_rc_general_error;
        }

    }

    if (!ctx.iv.in) {
        LOG_WARN("Using a weak IV, try specifying an IV");
    }

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

        TPMI_ALG_SYM_MODE objmode =
            public->publicArea.parameters.symDetail.sym.mode.sym;
        if (objmode == TPM2_ALG_NULL) {
            ctx.mode = TPM2_ALG_CFB;
        } else {
            ctx.mode = objmode;
        }
    }

    free(public);

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.encryption_key.ctx_path = value;
        break;
    case 'p':
        ctx.encryption_key.auth_str = value;
        break;
    case 'd':
        ctx.is_decrypt = 1;
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

static bool on_args(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected one input file, got: %d", argc);
        return false;
    }

    ctx.input_path = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth",        required_argument, NULL, 'p' },
        { "decrypt",     no_argument,       NULL, 'd' },
        { "iv",          required_argument, NULL, 't' },
        { "mode",        required_argument, NULL, 'G' },
        { "output",      required_argument, NULL, 'o' },
        { "key-context", required_argument, NULL, 'c' },
        { "pad",         no_argument,       NULL, 'e' },
    };

    *opts = tpm2_options_new("p:edi:o:c:G:t:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.encryption_key.ctx_path) {
        LOG_ERR("Expected a context file or handle, got none.");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.encryption_key.ctx_path,
            ctx.encryption_key.auth_str, &ctx.encryption_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid object key authorization");
        return rc;
    }

    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.input_path, &ctx.input_data_size, ctx.input_data);
    if (!result) {
        return tool_rc_general_error;
    }

    TPM2B_IV iv = { .size = sizeof(iv.buffer), .buffer = { 0 } };
    result = setup_alg_mode_and_iv_and_padding(ectx, &iv);
    if (!result) {
        LOG_ERR("Failure to setup key mode and or pkcs7 padding scheme.");
        return tool_rc_general_error;
    }

    return encrypt_decrypt(ectx, &iv);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.encryption_key.object.session);
}
