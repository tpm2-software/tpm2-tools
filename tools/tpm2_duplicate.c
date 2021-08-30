/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_openssl.h"
#include "tpm2_identity_util.h"

#define DEFAULT_DUPLICATE_ATTRS (TPMA_OBJECT_USERWITHAUTH|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT)

typedef struct tpm_duplicate_ctx tpm_duplicate_ctx;
struct tpm_duplicate_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        char *policy_str;
        tpm2_loaded_object object;
    } duplicable_key;

    struct {
        const char *ctx_path;
        tpm2_loaded_object object;
    } new_parent_key;

    const char *duplicate_key_public_file;
    const char *duplicate_key_private_file;

    const char *private_key_file;
    const char *parent_public_key_file;

    char *key_type;
    char *sym_key_in;
    char *sym_key_out;

    char *enc_seed_out;

    struct {
        UINT16 c :1;
        UINT16 C :1;
        UINT16 G :1;
        UINT16 i :1;
        UINT16 o :1;
        UINT16 r :1;
        UINT16 s :1;
        UINT16 U :1;
        UINT16 k :1;
        UINT16 u :1;
    } flags;

    char *cp_hash_path;
};

static tpm_duplicate_ctx ctx;

static tool_rc do_duplicate(ESYS_CONTEXT *ectx, TPM2B_DATA *in_key,
        TPMT_SYM_DEF_OBJECT *sym_alg, TPM2B_DATA **out_key,
        TPM2B_PRIVATE **duplicate, TPM2B_ENCRYPTED_SECRET **encrypted_seed) {

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_duplicate(ectx, &ctx.duplicable_key.object,
            &ctx.new_parent_key.object, in_key, sym_alg, out_key, duplicate,
            encrypted_seed, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    return tpm2_duplicate(ectx, &ctx.duplicable_key.object,
            &ctx.new_parent_key.object, in_key, sym_alg, out_key, duplicate,
            encrypted_seed, NULL);
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
        ctx.flags.G = 1;
        break;
    case 'i':
        ctx.sym_key_in = value;
        ctx.flags.i = 1;
        break;
    case 'o':
        ctx.sym_key_out = value;
        ctx.flags.o = 1;
        break;
    case 'C':
        ctx.new_parent_key.ctx_path = value;
        ctx.flags.C = 1;
        break;
    case 'c':
        ctx.duplicable_key.ctx_path = value;
        ctx.flags.c = 1;
        break;
    case 'r':
        ctx.duplicate_key_private_file = value;
        ctx.flags.r = 1;
        break;
    case 'u':
        ctx.duplicate_key_public_file = value;
        ctx.flags.u = 1;
        break;
    case 's':
        ctx.enc_seed_out = value;
        ctx.flags.s = 1;
        break;
    case 'U':
        ctx.parent_public_key_file = value;
        ctx.flags.U = 1;
        break;
    case 'k':
        ctx.private_key_file = value;
        ctx.flags.k = 1;
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
      { "auth",              required_argument, NULL, 'p'},
      { "policy",            required_argument, NULL, 'L'},
      { "wrapper-algorithm", required_argument, NULL, 'G'},
      { "private",           required_argument, NULL, 'r'},
      { "public",            required_argument, NULL, 'u'},
      { "private-key",       required_argument, NULL, 'k'},
      { "encryptionkey-in",  required_argument, NULL, 'i'},
      { "encryptionkey-out", required_argument, NULL, 'o'},
      { "encrypted-seed",    required_argument, NULL, 's'},
      { "parent-context",    required_argument, NULL, 'C'},
      { "parent-public",     required_argument, NULL, 'U'},
      { "key-context",       required_argument, NULL, 'c'},
      { "cphash",            required_argument, NULL,  0 },
    };

    *opts = tpm2_options_new("p:L:G:i:C:o:s:r:c:U:k:u:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_OPTIONAL_SAPI);

    return *opts != NULL;
}

/**
 * Check all options and report as many errors as possible via LOG_ERR.
 * @return
 *  true on success, false on failure.
 */
static bool check_options(void) {

    bool result = true;

    /* Check for NULL alg & (keyin | keyout) */
    if (ctx.flags.G == 0) {
        LOG_ERR("Expected key type to be specified via \"-G\","
                " missing option.");
        result = false;
    }

    /* If -G is not "null" we need an encryption key */
    if (strcmp(ctx.key_type, "null") && !ctx.flags.U) {
        if ((ctx.flags.i == 0) && (ctx.flags.o == 0)) {
            LOG_ERR("Expected in or out encryption key file \"-i/o\","
                    " missing option.");
            result = false;
        }
        if (ctx.flags.i && ctx.flags.o) {
            LOG_ERR("Expected either in or out encryption key file \"-i/o\","
                    " conflicting options.");
            result = false;
        }
    } else {
        if (ctx.flags.i || ctx.flags.o) {
            LOG_ERR("Expected neither in nor out encryption key file \"-i/o\","
                    " conflicting options.");
            result = false;
        }
    }

    if (ctx.flags.U != ctx.flags.k)
    {
        LOG_ERR("Conflicting options: remote public key and local private key must both be specified");
        result = false;
    } else
    if (!ctx.flags.U) {
	if (ctx.flags.C == 0) {
	    LOG_ERR("Expected new parent object to be specified via \"-C\","
		    " missing option.");
	    result = false;
	}

	if (ctx.flags.c == 0) {
	    LOG_ERR("Expected object to be specified via \"-c\","
		    " missing option.");
	    result = false;
	}

	if (ctx.flags.s == 0) {
	    LOG_ERR(
		    "Expected encrypted seed out filename to be specified via \"-S\","
			    " missing option.");
	    result = false;
	}

	if (ctx.flags.r == 0) {
	    LOG_ERR("Expected private key out filename to be specified via \"-r\","
		    " missing option.");
	    result = false;
	}
    }

    return result;
}

static bool set_key_algorithm(const char *algstr, TPMT_SYM_DEF_OBJECT * obj) {


    if (!strcmp(algstr, "null")) {
        obj->algorithm = TPM2_ALG_NULL;
        return true;
    } else if (!strcmp(algstr, "aes")) {
        obj->algorithm = TPM2_ALG_AES;
        obj->keyBits.aes = 128;
        obj->mode.aes = TPM2_ALG_CFB;
        return true;
    }

    LOG_ERR("The algorithm \"%s\" is not supported!", algstr);
    return false;
}

static tool_rc tpm2_create_duplicate(
    TPM2B_PUBLIC *parent_pub,
    TPM2B_SENSITIVE *privkey,
    TPM2B_PUBLIC *public,
    TPM2B_ENCRYPTED_SECRET *encrypted_seed)
{
    bool result;
    tool_rc rc = tool_rc_success;
    TSS2_RC rval;

    /*
     * Calculate the object name.
     */
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    result = tpm2_identity_create_name(public, &pubname);
    if (!result) {
        return false;
    }


    TPM2B_DIGEST * seed = &privkey->sensitiveArea.seedValue;
    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            parent_pub, &pubname, seed, &hmac_key, &enc_key);

    /*
     * Marshall the private key into a buffer
     */
    TPM2B_MAX_BUFFER marshalled_sensitive = TPM2B_EMPTY_INIT;
    size_t marshalled_sensitive_size = 0;
    rval = Tss2_MU_TPMT_SENSITIVE_Marshal(&privkey->sensitiveArea,
            marshalled_sensitive.buffer + sizeof(marshalled_sensitive.size),
            TPM2_MAX_DIGEST_BUFFER, &marshalled_sensitive_size);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing sensitive area");
        return false;
    }

    size_t marshalled_sensitive_size_info = 0;
    rval = Tss2_MU_UINT16_Marshal(marshalled_sensitive_size,
            marshalled_sensitive.buffer, sizeof(marshalled_sensitive.size),
            &marshalled_sensitive_size_info);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing sensitive area size");
        return false;
    }

    marshalled_sensitive.size = marshalled_sensitive_size
	+ marshalled_sensitive_size_info;

    /*
     * Compute the outer HMAC over the marshalled sensitive area
     * and encrypt it with the seed value.
     */
    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(parent_pub->publicArea.nameAlg,
            &pubname, &marshalled_sensitive, &hmac_key, &enc_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_duplicate_sensitive, &outer_hmac);

    /*
     * Build the private data structure for writing out
     */
    TPM2B_PRIVATE private = TPM2B_EMPTY_INIT;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_pub->publicArea.nameAlg);
    private.size = sizeof(parent_hash_size) + parent_hash_size
	+ encrypted_duplicate_sensitive.size;

    size_t hmac_size_offset = 0;
    rval = Tss2_MU_UINT16_Marshal(parent_hash_size, private.buffer,
            sizeof(parent_hash_size), &hmac_size_offset);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing hmac size");
        return false;
    }

    memcpy(private.buffer + hmac_size_offset, outer_hmac.buffer,
            parent_hash_size);
    memcpy(private.buffer + hmac_size_offset + parent_hash_size,
            encrypted_duplicate_sensitive.buffer,
            encrypted_duplicate_sensitive.size);

    /*
     * Write out the generated files
     */
    result = files_save_encrypted_seed(encrypted_seed, ctx.enc_seed_out);
    if (!result) {
        LOG_ERR("Failed to save encryption seed into file \"%s\"",
                ctx.enc_seed_out);
        rc = tool_rc_general_error;
        goto out;
    }

    result = files_save_private(&private, ctx.duplicate_key_private_file);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.duplicate_key_private_file);
        rc = tool_rc_general_error;
        goto out;
    }

    result = files_save_public(public, ctx.duplicate_key_public_file);
    if (!result) {
        LOG_ERR("Failed to save public key into file \"%s\"",
                ctx.duplicate_key_public_file);
        rc = tool_rc_general_error;
        goto out;
    }

out:
    return rc;
}

static void setup_default_attrs(TPMA_OBJECT *attrs, bool has_policy, bool has_auth) {

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

static tool_rc openssl_duplicate(void) {

    TPM2B_PUBLIC parent_public = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_SENSITIVE private = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;

    bool result = files_load_public(ctx.parent_public_key_file, &parent_public);
    if (!result)
        return tool_rc_general_error;

    TPMA_OBJECT attrs = 0;
    setup_default_attrs(&attrs, !!ctx.duplicable_key.policy_str, !!ctx.duplicable_key.auth_str);

    TPM2B_PUBLIC template = { 0 };
    tool_rc rc = tpm2_alg_util_public_init(
            ctx.key_type,
            NULL,          /* name-alg: does this matter? */
            NULL,          /* DO attributes matter? */
            ctx.duplicable_key.policy_str,
            attrs,
            &template);
    if (rc != tool_rc_success) {
        return rc;
    }

    result = tpm2_openssl_import_keys(
        &parent_public,
        &encrypted_seed,
        ctx.duplicable_key.auth_str,
        ctx.private_key_file,
        NULL, // passin
        &template,
        &private,
        &public
    );
    if (!result)
        return tool_rc_general_error;

    return tpm2_create_duplicate(&parent_public, &private, &public, &encrypted_seed);
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    tool_rc rc = tool_rc_general_error;
    TPMT_SYM_DEF_OBJECT sym_alg;
    TPM2B_DATA in_key;
    TPM2B_DATA* out_key = NULL;
    TPM2B_PRIVATE* duplicate;
    TPM2B_ENCRYPTED_SECRET* out_sym_seed;

    bool result = check_options();
    if (!result) {
        return tool_rc_option_error;
    }

    if (ctx.flags.U) {
        return openssl_duplicate();
    }

    rc = tpm2_util_object_load(ectx, ctx.new_parent_key.ctx_path,
            &ctx.new_parent_key.object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.duplicable_key.ctx_path,
            ctx.duplicable_key.auth_str, &ctx.duplicable_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid authorization");
        return rc;
    }

    result = set_key_algorithm(ctx.key_type, &sym_alg);
    if (!result) {
        return tool_rc_general_error;
    }

    if (ctx.flags.i) {
        in_key.size = 16;
        result = files_load_bytes_from_path(ctx.sym_key_in, in_key.buffer,
                &in_key.size);
        if (!result) {
            return tool_rc_general_error;
        }
        if (in_key.size != 16) {
            LOG_ERR("Invalid AES key size, got %u bytes, expected 16",
                    in_key.size);
            return tool_rc_general_error;
        }
    }

    rc = do_duplicate(ectx, ctx.flags.i ? &in_key : NULL, &sym_alg,
            ctx.flags.o ? &out_key : NULL, &duplicate, &out_sym_seed);
    if (rc != tool_rc_success || ctx.cp_hash_path) {
        return rc;
    }

    /* Maybe a false positive from scan-build but we'll check out_key anyway */
    if (ctx.flags.o) {
        if (out_key == NULL) {
            LOG_ERR("No encryption key from TPM ");
            rc = tool_rc_general_error;
            goto out;
        }
        result = files_save_bytes_to_file(ctx.sym_key_out, out_key->buffer,
                out_key->size);
        if (!result) {
            LOG_ERR("Failed to save encryption key out into file \"%s\"",
                    ctx.sym_key_out);
            rc = tool_rc_general_error;
            goto out;
        }
    }

    result = files_save_encrypted_seed(out_sym_seed, ctx.enc_seed_out);
    if (!result) {
        LOG_ERR("Failed to save encryption seed into file \"%s\"",
                ctx.enc_seed_out);
        rc = tool_rc_general_error;
        goto out;
    }

    result = files_save_private(duplicate, ctx.duplicate_key_private_file);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.duplicate_key_private_file);
        rc = tool_rc_general_error;
        goto out;
    }

    rc = tool_rc_success;

out:
    free(out_key);
    free(out_sym_seed);
    free(duplicate);

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.duplicable_key.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("duplicate", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
