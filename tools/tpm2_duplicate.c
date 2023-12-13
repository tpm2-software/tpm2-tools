/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_identity_util.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_duplicate_ctx tpm_duplicate_ctx;
struct tpm_duplicate_ctx {
    /*
     * Inputs
     */
    /* common */
    struct {
        const char *ctx_path;
        const char *auth_str;
        char *policy_str;
        char *attr_str;
        tpm2_loaded_object object;
    } duplicable_key;

    char *key_type;

    /* tpm2_duplicate only */
    struct {
        const char *ctx_path;
        tpm2_loaded_object object;
    } new_parent_key;

    TPMT_SYM_DEF_OBJECT sym_alg;

    char *sym_key_in;
    TPM2B_DATA in_key;

    /* tpm2_openssl */
    const char *in_private_key_file;
    TPM2B_SENSITIVE in_private_key_data;
    const char *in_parent_public_key_file;
    TPM2B_PUBLIC in_parent_public_key_data;

    bool is_openssl_duplicate;

    /*
     * Outputs
     */
    /*common*/
    const char *out_duplicate_key_private_file;
    char *enc_seed_out;

    /* tpm2_openssl */
    const char *out_duplicate_key_public_file;
    TPM2B_PUBLIC out_public_data;

    /*tpm2_duplicate*/
    TPM2B_ENCRYPTED_SECRET *out_sym_seed;

    char *sym_key_out;
    TPM2B_DATA *out_key;

    TPM2B_PRIVATE *out_private_data;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_duplicate_ctx ctx = {
    .out_public_data = TPM2B_EMPTY_INIT,
    .in_private_key_data = TPM2B_EMPTY_INIT,
    .in_parent_public_key_data = TPM2B_EMPTY_INIT,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc duplicate(ESYS_CONTEXT *ectx) {

    return tpm2_duplicate(ectx, &ctx.duplicable_key.object,
        &ctx.new_parent_key.object, &ctx.in_key, &ctx.sym_alg, &ctx.out_key,
        &ctx.out_private_data, &ctx.out_sym_seed, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
}

static tool_rc openssl_create_duplicate(void) {

    /*
     * Calculate the object name.
     */
    tool_rc rc = tool_rc_success;
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    bool result = tpm2_identity_create_name(&ctx.out_public_data, &pubname);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    TPM2B_DIGEST * seed = &ctx.in_private_key_data.sensitiveArea.seedValue;
    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        &ctx.in_parent_public_key_data, &pubname, seed, &hmac_key, &enc_key);

    /*
     * Marshall the private key into a buffer
     */
    TPM2B_MAX_BUFFER marshalled_sensitive = TPM2B_EMPTY_INIT;
    size_t marshalled_sensitive_size = 0;
    TSS2_RC rval = Tss2_MU_TPMT_SENSITIVE_Marshal(
        &ctx.in_private_key_data.sensitiveArea,
        marshalled_sensitive.buffer + sizeof(marshalled_sensitive.size),
        TPM2_MAX_DIGEST_BUFFER, &marshalled_sensitive_size);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing sensitive area");
        rc = tool_rc_general_error;
        goto out;
    }

    size_t marshalled_sensitive_size_info = 0;
    rval = Tss2_MU_UINT16_Marshal(marshalled_sensitive_size,
        marshalled_sensitive.buffer, sizeof(marshalled_sensitive.size),
        &marshalled_sensitive_size_info);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing sensitive area size");
        rc = tool_rc_general_error;
        goto out;
    }

    marshalled_sensitive.size =
        marshalled_sensitive_size + marshalled_sensitive_size_info;

    /*
     * Compute the outer HMAC over the marshalled sensitive area
     * and encrypt it with the seed value.
     */
    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(
        ctx.in_parent_public_key_data.publicArea.nameAlg,
        &pubname, &marshalled_sensitive, &hmac_key, &enc_key,
        &ctx.in_parent_public_key_data.publicArea.parameters.rsaDetail.symmetric,
        &encrypted_duplicate_sensitive, &outer_hmac);

    /*
     * Build the private data structure for writing out
     */
    TPM2B_PRIVATE private = TPM2B_EMPTY_INIT;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(
        ctx.in_parent_public_key_data.publicArea.nameAlg);

    private.size = sizeof(parent_hash_size) +
        parent_hash_size + encrypted_duplicate_sensitive.size;

    size_t hmac_size_offset = 0;
    rval = Tss2_MU_UINT16_Marshal(parent_hash_size, private.buffer,
        sizeof(parent_hash_size), &hmac_size_offset);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing hmac size");
        rc = tool_rc_general_error;
        goto out;
    }

    memcpy(private.buffer + hmac_size_offset, outer_hmac.buffer,
        parent_hash_size);
    memcpy(private.buffer + hmac_size_offset + parent_hash_size,
        encrypted_duplicate_sensitive.buffer,
        encrypted_duplicate_sensitive.size);

    ctx.out_private_data = malloc(private.size + sizeof(private.size));
    memcpy(ctx.out_private_data, &private, private.size + sizeof(private.size));

out:
    return rc;
}

#define DEFAULT_DUPLICATE_ATTRS (TPMA_OBJECT_USERWITHAUTH|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT)
static void setup_default_attrs(TPMA_OBJECT *attrs, bool has_policy,
    bool has_auth) {

    /* Handle Default Setup */
    *attrs = DEFAULT_DUPLICATE_ATTRS;

    /*
     * IMPORTANT: if the object we're creating has a policy and NO authvalue, turn off userwith auth
     * so empty passwords don't work on the object.
     */
    if (has_policy && !has_auth) {
        *attrs &= ~TPMA_OBJECT_USERWITHAUTH;
    }
}

static tool_rc process_openssl_duplicate(void) {

    bool result = files_load_public(ctx.in_parent_public_key_file,
        &ctx.in_parent_public_key_data);
    if (!result) {
        return tool_rc_general_error;
    }

    TPMA_OBJECT attrs = 0;
    bool is_policy_specified = (ctx.duplicable_key.policy_str != 0);
    bool is_auth_specified = (ctx.duplicable_key.auth_str != 0);
    setup_default_attrs(&attrs, is_policy_specified, is_auth_specified);

    TPM2B_PUBLIC template = { 0 };
    tool_rc rc = tpm2_alg_util_public_init(ctx.key_type, 0, ctx.duplicable_key.attr_str,
        ctx.duplicable_key.policy_str, attrs, &template);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;
    result = tpm2_openssl_import_keys(&ctx.in_parent_public_key_data, &encrypted_seed,
        ctx.duplicable_key.auth_str, ctx.in_private_key_file, 0, &template,
        &ctx.in_private_key_data, &ctx.out_public_data);
    if (!result) {
        return tool_rc_general_error;
    }

    ctx.out_sym_seed = malloc(encrypted_seed.size +
        sizeof(encrypted_seed.size));
    memcpy(ctx.out_sym_seed, &encrypted_seed,
        encrypted_seed.size + sizeof(encrypted_seed.size));

    return tool_rc_success;
}

static bool set_key_algorithm(const char *algstr, TPMT_SYM_DEF_OBJECT * obj) {

    bool is_algstr_null = (strcmp(algstr, "null") == 0);
    if (is_algstr_null) {
        obj->algorithm = TPM2_ALG_NULL;
        return true;
    }

    bool is_algstr_aes = (strcmp(algstr, "aes") == 0);
    if (is_algstr_aes) {
        obj->algorithm = TPM2_ALG_AES;
        obj->keyBits.aes = 128;
        obj->mode.aes = TPM2_ALG_CFB;
        return true;
    }

    LOG_ERR("The algorithm \"%s\" is not supported!", algstr);
    return false;
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path && !ctx.is_openssl_duplicate) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch && !ctx.is_openssl_duplicate) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    if (ctx.sym_key_out && !ctx.is_openssl_duplicate) {
        if (ctx.out_key == 0) {
            LOG_ERR("No encryption key from TPM ");
            rc = tool_rc_general_error;
            goto out;
        }
        is_file_op_success = files_save_bytes_to_file(ctx.sym_key_out,
            ctx.out_key->buffer, ctx.out_key->size);
        if (!is_file_op_success) {
            LOG_ERR("Failed to save encryption key out into file \"%s\"",
                    ctx.sym_key_out);
            rc = tool_rc_general_error;
            goto out;
        }
    }

    is_file_op_success = files_save_encrypted_seed(ctx.out_sym_seed, ctx.enc_seed_out);
    if (!is_file_op_success) {
        LOG_ERR("Failed to save encryption seed into file \"%s\"",
                ctx.enc_seed_out);
        rc = tool_rc_general_error;
        goto out;
    }

    is_file_op_success = files_save_private(ctx.out_private_data,
        ctx.out_duplicate_key_private_file);
    if (!is_file_op_success) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.out_duplicate_key_private_file);
        rc = tool_rc_general_error;
        goto out;
    }

    if (ctx.is_openssl_duplicate) {
        is_file_op_success = files_save_public(&ctx.out_public_data,
            ctx.out_duplicate_key_public_file);
        if (!is_file_op_success) {
            LOG_ERR("Failed to save public key into file \"%s\"",
                ctx.out_duplicate_key_public_file);
            rc = tool_rc_general_error;
            goto out;
        }
    }

out:
    return rc;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 3.a Command specific initializations
     *
     * No further processing as duplication is handled without going to the TPM
     * 
     */
    if (ctx.is_openssl_duplicate) {
        return process_openssl_duplicate();
    }

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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.duplicable_key.ctx_path,
            ctx.duplicable_key.auth_str, &ctx.duplicable_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid authorization");
        return rc;
    }

    /* Object #2 */
    rc = tpm2_util_object_load(ectx, ctx.new_parent_key.ctx_path,
            &ctx.new_parent_key.object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3.b Command specific initializations
     */
    bool result = set_key_algorithm(ctx.key_type, &ctx.sym_alg);
    if (!result) {
        return tool_rc_general_error;
    }

    if (ctx.sym_key_in) {
        ctx.in_key.size = 16;
        result = files_load_bytes_from_path(ctx.sym_key_in, ctx.in_key.buffer,
                &ctx.in_key.size);
        if (!result) {
            return tool_rc_general_error;
        }
        if (ctx.in_key.size != 16) {
            LOG_ERR("Invalid AES key size, got %u bytes, expected 16",
                    ctx.in_key.size);
            return tool_rc_general_error;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.duplicable_key.object.session,
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

    bool result = true;
    /* Check for NULL alg & (keyin | keyout) */
    if (!ctx.key_type) {
        LOG_ERR("Expected key type to be specified via \"-G\","
                " missing option.");
        result = false;
    }

    /* If -G is not "null" we need an encryption key */
    bool is_key_type_not_null = strcmp(ctx.key_type, "null");
    bool is_in_or_out_enc_key_expected =
        (is_key_type_not_null && !ctx.in_parent_public_key_file);

    if (is_in_or_out_enc_key_expected) {
        if (!ctx.sym_key_in && !ctx.sym_key_out) {
            LOG_ERR("Expected in or out encryption key file \"-i/o\","
                    " missing option.");
            result = false;
        }

        if (ctx.sym_key_in && ctx.sym_key_out) {
            LOG_ERR("Expected either in or out encryption key file \"-i/o\","
                    " conflicting options.");
            result = false;
        }
    }

    if (!is_in_or_out_enc_key_expected && (ctx.sym_key_in || ctx.sym_key_out)) {
        LOG_ERR("Expected neither in nor out encryption key file \"-i/o\","
                " conflicting options.");
        result = false;
    }

    bool is_parent_public_specified = (ctx.in_parent_public_key_file != 0);
    bool is_local_private_specified = (ctx.in_private_key_file != 0);
    bool is_parent_public_and_local_private_availability_conflict =
        (is_parent_public_specified != is_local_private_specified);

    if (is_parent_public_and_local_private_availability_conflict) {
        LOG_ERR("Conflicting options: remote public key and local private key "
                "must both be specified");
        result = false;
    }

    bool is_neither_parent_public_nor_local_private_spcified =
        (!is_parent_public_specified && !is_local_private_specified);
    if (is_neither_parent_public_nor_local_private_spcified) {
	    if (!ctx.new_parent_key.ctx_path) {
	        LOG_ERR("Expected new parent object to be specified via \"-C\","
	        " missing option.");
	        result = false;
	    }

	    if (!ctx.duplicable_key.ctx_path) {
	        LOG_ERR("Expected object to be specified via \"-c\","
	        " missing option.");
	        result = false;
	    }

	    if (!ctx.enc_seed_out) {
	        LOG_ERR(
	        "Expected encrypted seed out filename to be specified via \"-S\","
	    	    " missing option.");
	        result = false;
	    }

	    if (!ctx.out_duplicate_key_private_file) {
	        LOG_ERR("Expected private key out filename to be specified via \"-r\","
	        " missing option.");
	        result = false;
	    }
    }

    return result ? tool_rc_success : tool_rc_option_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'p':
        ctx.duplicable_key.auth_str = value;
        break;
    case 'L':
        ctx.duplicable_key.policy_str = value;
        break;
    case 'G':
        ctx.key_type = value;
        break;
    case 'i':
        ctx.sym_key_in = value;
        break;
    case 'o':
        ctx.sym_key_out = value;
        break;
    case 'C':
        ctx.new_parent_key.ctx_path = value;
        break;
    case 'c':
        ctx.duplicable_key.ctx_path = value;
        break;
    case 'r':
        ctx.out_duplicate_key_private_file = value;
        break;
    case 'u':
        ctx.out_duplicate_key_public_file = value;
        break;
    case 's':
        ctx.enc_seed_out = value;
        break;
    case 'U':
        ctx.in_parent_public_key_file = value;
        ctx.is_openssl_duplicate = true;
        break;
    case 'k':
        ctx.in_private_key_file = value;
        break;
    case 'a':
        ctx.duplicable_key.attr_str = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth",              required_argument, 0, 'p'},
      { "policy",            required_argument, 0, 'L'},
      { "wrapper-algorithm", required_argument, 0, 'G'},
      { "key-algorithm",     required_argument, 0, 'G'},
      { "private",           required_argument, 0, 'r'},
      { "public",            required_argument, 0, 'u'},
      { "private-key",       required_argument, 0, 'k'},
      { "encryptionkey-in",  required_argument, 0, 'i'},
      { "encryptionkey-out", required_argument, 0, 'o'},
      { "encrypted-seed",    required_argument, 0, 's'},
      { "parent-context",    required_argument, 0, 'C'},
      { "parent-public",     required_argument, 0, 'U'},
      { "key-context",       required_argument, 0, 'c'},
      { "attributes",        required_argument, 0, 'a'},
      { "cphash",            required_argument, 0,  0 },
    };

    *opts = tpm2_options_new("p:L:G:i:C:o:s:r:c:U:k:u:a:", ARRAY_LEN(topts), topts,
            on_option, 0, TPM2_OPTIONS_OPTIONAL_SAPI);

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
    rc = ctx.is_openssl_duplicate ? openssl_create_duplicate() : duplicate(ectx);
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
    free(ctx.out_key);
    free(ctx.out_sym_seed);
    free(ctx.out_private_data);
    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.duplicable_key.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("duplicate", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
