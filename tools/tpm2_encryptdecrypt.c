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
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

#define MAX_INPUT_DATA_SIZE UINT16_MAX
#define MAX_SESSIONS 3
typedef struct tpm_encrypt_decrypt_ctx tpm_encrypt_decrypt_ctx;
struct tpm_encrypt_decrypt_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } encryption_key;

    TPMI_YES_NO is_decrypt;

    uint8_t input_data[MAX_INPUT_DATA_SIZE];
    uint16_t input_data_size;

    const char *input_path;

    uint8_t padded_block_len;
    bool is_padding_option_enabled;

    TPMI_ALG_SYM_MODE mode;
    struct {
        char *in_path;
        char *out_path;
    } iv;

    TPM2B_IV *iv_in;

    /*
     * Outputs
     */
    char *out_file_path;
    FILE *out_file_ptr;
    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_encrypt_decrypt_ctx ctx = {
    .mode = TPM2_ALG_NULL,
    .input_data_size = MAX_INPUT_DATA_SIZE,
    .padded_block_len = TPM2_MAX_SYM_BLOCK_SIZE,
    .is_padding_option_enabled = false,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static bool evaluate_pkcs7_padding_requirements(uint16_t remaining_bytes,
    bool expected) {

    if (!ctx.is_padding_option_enabled) {
        return false;
    }

    /*
     * If it is a decrypt operation, we don't expect to apply/append padding to
     * encrypted ciphertext prior to decrypting with tpm2_encryptdecrypt.
     *
     * If it is an encrypt operation, we do expect to apply/append padding to
     * plaintext prior to encrypting with tpm2_encryptdecrypt.
     *
     * If it is a decrypt operation, we do expect to strip padding from
     * decrypted text after decrypting with tpm2_encryptdecrypt.
     *
     * If it is an encrypt operation, we don't expect to perfom pad-stripping of
     * encrypted ciphertext after encrypting with tpm2_encryptdecrypt.
     */
    if (ctx.is_decrypt != expected) {
        return false;
    }

    /*
     * If ctx.mode was not specified, cfb was chosen as default.
     *
     * For other modes of encryption, such as CTR or OFB or CFB,
     * padding is not required because In these cases the ciphertext is
     * always the same length as the plaintext, and a padding
     * method is not applicable.
     */
    if (ctx.mode != TPM2_ALG_CBC && ctx.mode != TPM2_ALG_ECB) {
        return false;
    }

    /*
     * Only apply / strip padding to the last block.
     */
    bool is_last_block = (remaining_bytes <= TPM2_MAX_DIGEST_BUFFER &&
        remaining_bytes > 0);
    if (!is_last_block) {
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

    *pad_data = out_data->buffer[out_data->size - 1];

    if (*pad_data > ctx.padded_block_len) {
      LOG_WARN("Padding data is larger than block length: %d", *pad_data);
      return;
    }

    for (uint8_t offset = *pad_data; offset > 1; --offset) {
      if (out_data->buffer[out_data->size - offset] != *pad_data) {
        LOG_WARN("Inconsistent padding within decrypted input");
        return;
      }
    }

    out_data->size -= *pad_data;
}

static tool_rc encrypt_decrypt(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_success;
    uint8_t pad_data = 0;
    UINT16 data_offset = 0;
    uint16_t remaining_bytes = ctx.input_data_size;
    while (remaining_bytes > 0) {
        TPM2B_MAX_BUFFER in_data = {
            .size = (remaining_bytes > TPM2_MAX_DIGEST_BUFFER) ?
                    TPM2_MAX_DIGEST_BUFFER : remaining_bytes,
        };

        if (pad_data == 0) {
            append_pkcs7_padding_data_to_input(&pad_data, &in_data.size,
                &remaining_bytes);
        }

        memcpy(in_data.buffer, &ctx.input_data[data_offset], in_data.size);

        TPM2B_MAX_BUFFER *out_data = 0;
        TPM2B_IV *iv_out = 0;
        rc = tpm2_encryptdecrypt(ectx, &ctx.encryption_key.object,
            ctx.is_decrypt, ctx.mode, ctx.iv_in, &in_data, &out_data, &iv_out,
            &ctx.cp_hash, ctx.parameter_hash_algorithm);
        if (rc != tool_rc_success) {
            goto out;
        }
        data_offset += in_data.size;

        if (ctx.is_command_dispatch) {
            /*
             * Copy iv_out iv_in to use it in next loop iteration.
             * This copy is also output from the tool for further chaining.
             */
            if (ctx.mode != TPM2_ALG_ECB) {
                assert(ctx.iv_in);
                assert(iv_out);
                *ctx.iv_in = *iv_out;
                free(iv_out);
            }

            strip_pkcs7_padding_data_from_output(&pad_data, out_data,
                    &remaining_bytes);

            bool result = files_write_bytes(ctx.out_file_ptr, out_data->buffer,
                    out_data->size);
            free(out_data);
            if (!result) {
                LOG_ERR("Failed to save output data to file");
                goto out;
            }
        }

        remaining_bytes -= in_data.size;
    }

out:
    if (ctx.out_file_ptr != stdout) {
        fclose(ctx.out_file_ptr);
    }

    return rc;
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    /*
     * iv_in here is the copy of final iv_out from the loop above.
     */
    if (ctx.iv.out_path && ctx.iv_in) {
        is_file_op_success = files_save_bytes_to_file(ctx.iv.out_path,
            ctx.iv_in->buffer, ctx.iv_in->size);
    }
    if (!is_file_op_success) {
        rc = tool_rc_general_error;
    }

    return rc;
}

static bool setup_alg_mode(ESYS_CONTEXT *ectx) {

    TPM2B_PUBLIC *public;
    tool_rc rc = tpm2_readpublic(ectx, ctx.encryption_key.object.tr_handle,
        &public, 0, 0);
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

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.encryption_key.ctx_path,
            ctx.encryption_key.auth_str, &ctx.encryption_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid object key authorization");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(0,
            ctx.input_path, &ctx.input_data_size, ctx.input_data);
    if (!result) {
        LOG_ERR("Failed to read in the input.");
        return tool_rc_general_error;
    }

    if (ctx.cp_hash_path && ctx.input_data_size > TPM2_MAX_DIGEST_BUFFER) {
        LOG_ERR("Cannot calculate cpHash for buffer larger than max digest "
                "buffer.");
        return tool_rc_general_error;
    }

    TPM2B_IV iv_start = {
        .size = sizeof(iv_start.buffer), .buffer = { 0 },
    };

    if (ctx.iv.in_path) {
        unsigned long file_size;
        result = files_get_file_size_path(ctx.iv.in_path, &file_size);
        if (!result) {
            LOG_ERR("Could not retrieve iv file size.");
            return tool_rc_general_error;
        }

        if (file_size != iv_start.size) {
            LOG_ERR("Iv should be 16 bytes, got %lu", file_size);
            return tool_rc_general_error;
        }

        result = files_load_bytes_from_path(ctx.iv.in_path, iv_start.buffer,
            &iv_start.size);
        if (!result) {
            LOG_ERR("Could not load the iv from the file.");
            return tool_rc_general_error;
        }
    }

    if (ctx.mode == TPM2_ALG_ECB) {
        ctx.iv_in = 0;
    } else {
        ctx.iv_in = malloc(iv_start.size + sizeof(iv_start));
        ctx.iv_in->size = iv_start.size;
        memcpy(ctx.iv_in->buffer, &iv_start.buffer, iv_start.size);
    }

    result = setup_alg_mode(ectx);
    if (!result) {
        LOG_ERR("Failure to setup key mode.");
        return tool_rc_general_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.encryption_key.object.session,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);
    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (!ctx.encryption_key.ctx_path) {
        LOG_ERR("Expected a context file or handle, got none.");
        return tool_rc_option_error;
    }

    ctx.out_file_ptr = ctx.out_file_path ?
        fopen(ctx.out_file_path, "wb+") : stdout;
    if (!ctx.out_file_ptr) {
        LOG_ERR("Could not open file \"%s\", error: %s", ctx.out_file_path,
                strerror(errno));
        return tool_rc_general_error;
    }

    if (!ctx.iv.in_path) {
        LOG_WARN("Using a weak IV, try specifying an IV");
    }

    return tool_rc_success;
}

static bool on_args(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected one input file, got: %d", argc);
        return false;
    }

    ctx.input_path = argv[0];

    return true;
}

static void parse_iv(char *value) {

    ctx.iv.in_path = value;

    char *split = strchr(value, ':');
    if (split) {
        *split = '\0';
        split++;
        if (split) {
            ctx.iv.out_path = split;
        }
    }
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
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth",        required_argument, 0, 'p' },
        { "decrypt",     no_argument,       0, 'd' },
        { "iv",          required_argument, 0, 't' },
        { "mode",        required_argument, 0, 'G' },
        { "output",      required_argument, 0, 'o' },
        { "key-context", required_argument, 0, 'c' },
        { "pad",         no_argument,       0, 'e' },
        { "cphash",      required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("p:edi:o:c:G:t:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = encrypt_decrypt(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    free(ctx.iv_in);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.encryption_key.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("encryptdecrypt", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
