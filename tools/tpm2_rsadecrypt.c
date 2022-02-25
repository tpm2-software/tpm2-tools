/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *input_path;

    TPMT_RSA_DECRYPT scheme;
    const char *scheme_str;

    /*
     * Outputs
     */
    char *output_file_path;
    TPM2B_PUBLIC_KEY_RSA *message;
    FILE *foutput;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_rsadecrypt_ctx ctx = {
    .scheme = { .scheme = TPM2_ALG_RSAES },
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc rsa_decrypt(ESYS_CONTEXT *ectx) {

    return tpm2_rsa_decrypt(ectx, &ctx.key.object, &ctx.cipher_text,
        &ctx.scheme, &ctx.label, &ctx.message, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
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
    is_file_op_success = files_write_bytes(ctx.foutput, ctx.message->buffer,
        ctx.message->size);
    if (ctx.foutput != stdout) {
        fclose(ctx.foutput);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
        ctx.key.auth_str, &ctx.key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    ctx.foutput = ctx.output_file_path ?
        fopen(ctx.output_file_path, "wb+") : stdout;
    if (!ctx.foutput) {
        return tool_rc_general_error;
    }

    TPM2B_PUBLIC *key_public_info = 0;
    rc = tpm2_readpublic(ectx, ctx.key.object.tr_handle, &key_public_info,
        0, 0);
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

        if (rc != tool_rc_success) {
            goto out;
        }
    }

    /*
     * Get enc data blob
     */
    ctx.cipher_text.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(0,
            ctx.input_path, &ctx.cipher_text.size, ctx.cipher_text.buffer);
    if (!result) {
        rc = tool_rc_general_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.key.object.session,
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

out:
    Esys_Free(key_public_info);
    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (!ctx.key.ctx_path) {
        LOG_ERR("Expected argument -c.");
        return tool_rc_option_error;
    }

    if (ctx.output_file_path && ctx.cp_hash_path) {
        LOG_ERR("Cannout decrypt when calculating cphash");
        return tool_rc_option_error;
    }

    return tool_rc_success;
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
        ctx.scheme_str = value;
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
      { "auth",        required_argument, 0, 'p' },
      { "output",      required_argument, 0, 'o' },
      { "key-context", required_argument, 0, 'c' },
      { "scheme",      required_argument, 0, 's' },
      { "label",       required_argument, 0, 'l' },
      { "cphash",      required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("p:o:c:s:l:", ARRAY_LEN(topts), topts, on_option,
        on_args, 0);

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
    rc = rsa_decrypt(ectx);
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
    free(ctx.message);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.key.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("rsadecrypt", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
