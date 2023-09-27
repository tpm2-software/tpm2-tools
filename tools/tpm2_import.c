/* SPDX-License-Identifier: BSD-3-Clause */

//**********************************************************************;
// Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
// Licensed under the Apache License 2.0 (the "License"). You may not use
// this file except in compliance with the License. You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0)
//
// See Victor Shoup, "OAEP reconsidered," Nov. 2000, <URL:
// http://www.shoup.net/papers/oaep.ps.Z> for problems with the security
// proof for the original OAEP scheme, which EME-OAEP is based on. A new
// proof can be found in E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern,
// "RSA-OEAP is Still Alive!", Dec. 2000, <URL:http://eprint.iacr.org/2000/061/>.
// The new proof has stronger requirements for the underlying permutation:
// "partial-one-wayness" instead of one-wayness. For the RSA function, this
// is an equivalent notion.
//**********************************************************************;
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_errata.h"
#include "tpm2_identity_util.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_import_ctx tpm_import_ctx;
struct tpm_import_ctx {
    /*
     * Inputs
     */

    /* common */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    char *input_key_file;
    char *policy;
    TPMT_SYM_DEF_OBJECT sym_alg;
    TPM2B_PRIVATE duplicate;
    TPM2B_DATA enc_sensitive_key;
    TPM2B_ENCRYPTED_SECRET encrypted_seed;
    /* SSL */
    char *parent_key_public_file;
    char *name_alg;
    char *attrs;
    char *key_auth_str;
    char *passin;
    char *object_alg;
    /* TPM */
    char *input_seed_file;
    char *input_enc_key_file;
    bool import_tpm;

    /*
     * Outputs
     */
    /* common */
    char *public_key_file; // TPM input, SSL output
    TPM2B_PUBLIC public;
    char *private_key_file;
    TPM2B_PRIVATE *imported_private;
    bool autoflush;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_import_ctx ctx = {
    .sym_alg.algorithm = TPM2_ALG_NULL,
    .enc_sensitive_key = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .encrypted_seed = TPM2B_EMPTY_INIT,
    .duplicate = TPM2B_EMPTY_INIT,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .autoflush = false,
};

static tool_rc import(ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    tool_rc rc = tpm2_import(ectx, &ctx.parent.object, &ctx.enc_sensitive_key,
        &ctx.public, &ctx.duplicate, &ctx.encrypted_seed, &ctx.sym_alg,
        &ctx.imported_private, &ctx.cp_hash, ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        return rc;
    }
    if ((ctx.autoflush || tpm2_util_env_yes(TPM2TOOLS_ENV_AUTOFLUSH)) &&
        ctx.parent.object.path &&
        (ctx.parent.object.handle & TPM2_HR_RANGE_MASK) == TPM2_HR_TRANSIENT) {
        rval = Esys_FlushContext(ectx, ctx.parent.object.tr_handle);
        if (rval != TPM2_RC_SUCCESS) {
            return tool_rc_general_error;
        }
    }
    return tool_rc_success;
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
    assert(ctx.imported_private);
    bool result = files_save_private(ctx.imported_private, ctx.private_key_file);
    Esys_Free(ctx.imported_private);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.private_key_file);
        return tool_rc_general_error;
    }

    /*
     * Public information generated for an SSL imported key
     */
    if (!ctx.import_tpm) {
        is_file_op_success = files_save_public(&ctx.public,
            ctx.public_key_file);
        if (!is_file_op_success) {
            LOG_ERR("Failed to save TPM2B_PUBLIC for the input SSL key");
            return tool_rc_general_error;
        }

        tpm2_util_public_to_yaml(&ctx.public, 0);
    }

    return tool_rc_success;
}

static bool create_import_key_private_data(TPMI_ALG_HASH parent_name_alg,
    TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive, TPM2B_DIGEST *outer_hmac) {

    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);
    ctx.duplicate.size = sizeof(parent_hash_size) + parent_hash_size +
        encrypted_duplicate_sensitive->size;

    size_t hmac_size_offset = 0;
    TSS2_RC rval = Tss2_MU_UINT16_Marshal(parent_hash_size,
        ctx.duplicate.buffer, sizeof(parent_hash_size), &hmac_size_offset);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing parent hash size");
        return false;
    }

    memcpy(ctx.duplicate.buffer + hmac_size_offset, outer_hmac->buffer,
        parent_hash_size);
    memcpy(ctx.duplicate.buffer + hmac_size_offset + parent_hash_size,
        encrypted_duplicate_sensitive->buffer,
        encrypted_duplicate_sensitive->size);

    return true;
}

static void setup_default_attrs(TPMA_OBJECT *attrs, bool has_policy,
    bool has_auth) {

    /* Handle Default Setup */
    *attrs = DEFAULT_CREATE_ATTRS;

    /* imported objects arn't created inside of the TPM so this gets turned down */
    *attrs &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
    *attrs &= ~TPMA_OBJECT_FIXEDTPM;
    *attrs &= ~TPMA_OBJECT_FIXEDPARENT;

    /* The default for a keyedhash object with no scheme is just for sealing */
    if (!strcmp("keyedhash", ctx.object_alg)) {
        *attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
        *attrs &= ~TPMA_OBJECT_DECRYPT;
    } else if (!strncmp("hmac", ctx.object_alg, 4)) {
        *attrs &= ~TPMA_OBJECT_DECRYPT;
    }

    /*
     * IMPORTANT: if the object we're creating has a policy and NO authvalue, turn off userwith auth
     * so empty passwords don't work on the object.
     */
    if (has_policy && !has_auth) {
        *attrs &= ~TPMA_OBJECT_USERWITHAUTH;
    }
}

static tool_rc process_input_ossl_import(ESYS_CONTEXT *ectx) {

    /*
     * Load the parent public file, or read it from the TPM if not specified.
     * We need this information for encrypting the protection seed.
     */
    bool free_ppub = false;
    TPM2B_PUBLIC ppub = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *parent_pub = 0;
    bool is_file_op_success = true;
    tool_rc rc = tool_rc_success;
    if (ctx.parent_key_public_file) {
        is_file_op_success = files_load_public(ctx.parent_key_public_file,
            &ppub);
        parent_pub = &ppub;
    } else {
        rc = tpm2_readpublic(ectx, ctx.parent.object.tr_handle, &parent_pub,
            0, 0);
        free_ppub = true;
    }

    if (!is_file_op_success || rc != tool_rc_success) {
        LOG_ERR("Failed loading parent key public.");
        goto out;
    }

    /*
     * Following is the reference from Table 41 of TPM Specifications Part 3 and
     * is used to construct a duplication wrapper on an ssl key
     *
     * 1. encryptionKey - Generate(ossl-RAND)
     * 2. objectPublic  - Derive-from-private(ossl) and add attrs
     * 3. duplicate - Generate(ossl)
     *                  - InnerWrapper
     *                      - innerIntegrity ≔ HnameAlg (sensitive || name) (37)
     *                          - encSensitive ≔ CFBpSymAlg (symKey, 0, innerIntegrity || sensitive) (38)
     *                              - symKey = `encryptionKey` parameter in TPM2_Duplicate() or a value from the RNG in step 1
     *                  - OuterWrapper
     *                      - dupSensitive ≔ CFBnpSymAlg (symKey, 0, encSensitive) (41)
     *                          - symKey ≔ KDFa (npNameAlg, seed, “STORAGE”, Name, 0 , bits) (40)
     *                              - seed is from the sensitive structure in (37) (38)
     *                      - outerHMAC ≔ HMACnpNameAlg (HMACkey, dupSensitive || Name) (43)
     *                          - HMACkey ≔ KDFa (npNameAlg, seed, “INTEGRITY”, 0, 0, bits) (42)
     *                              - seed is from the sensitive structure in (37) (38)
     * 4. inSymSeed = seed in (37) (38) from private->sensitive or RNG. -> ctx.encrypted_seed
     * 5. symmetricAlg
     */

    /* encryptionKey */
    /*
     * Create the protection encryption key that gets encrypted with the parents
     * public key.
     */
    ctx.enc_sensitive_key.size =
        parent_pub->publicArea.parameters.rsaDetail.symmetric.keyBits.sym / 8;
    if(ctx.enc_sensitive_key.size < 16) {
        LOG_ERR("Calculated wrapping keysize is less than 16 bytes, got: %u",
            ctx.enc_sensitive_key.size);
        rc = tool_rc_general_error;
        goto out;
    }

    int ossl_rc = RAND_bytes(ctx.enc_sensitive_key.buffer,
        ctx.enc_sensitive_key.size);
    if (ossl_rc != 1) {
        LOG_ERR("RAND_bytes failed: %s", ERR_error_string(ERR_get_error(), 0));
        rc = tool_rc_general_error;
        goto out;
    }

    /* objectPublic */
    /*
     * start with the tools default set and turn off the ones that don't make sense
     * If the user specified their own values, tpm2_alg_util_public_init will use that,
     * so this is just the default case.
     * */
    TPMA_OBJECT attrs = 0;
    if (!ctx.attrs) {
        setup_default_attrs(&attrs, !!ctx.policy, !!ctx.key_auth_str);
    }
    /*
     * Backwards Compat: the tool sets name-alg by default to the parent name alg if not specified
     * but the tpm2_alg_util_public_init defaults to sha256. Specify the alg if not specified.
     */
    if (!ctx.name_alg) {
        ctx.name_alg = (char *)tpm2_alg_util_algtostr(
            parent_pub->publicArea.nameAlg, tpm2_alg_util_flags_hash);
        if (!ctx.name_alg) {
            LOG_ERR("Invalid parent name algorithm, got 0x%x",
                    parent_pub->publicArea.nameAlg);
            rc = tool_rc_general_error;
            goto out;
        }
    }

    TPM2B_PUBLIC template = { 0 };
    rc = tpm2_alg_util_public_init(ctx.object_alg, ctx.name_alg,
        ctx.attrs, ctx.policy, attrs, &template);
    if (rc != tool_rc_success) {
        goto out;
    }

    TPM2B_SENSITIVE private_sensitive = TPM2B_EMPTY_INIT;
    /*
     * This call also generates a seed, places it in TPM2B_SENSITIVE and returns
     * it in ctx.encrypted_seed
     */
    /* inSymSeed */
    bool result = tpm2_openssl_import_keys(parent_pub, &ctx.encrypted_seed,
        ctx.key_auth_str, ctx.input_key_file, ctx.passin, &template,
        &private_sensitive, &ctx.public);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    /* duplicate */
    /*
     * Calculate the object name.
     */
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    result = tpm2_identity_create_name(&ctx.public, &pubname);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    /*
     * Here seed is pointing to the plaintext or unencrypted ctx.encrypted_seed
     */
    TPM2B_DIGEST *seed = &private_sensitive.sensitiveArea.seedValue;
    result = tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        parent_pub, &pubname, seed, &hmac_key, &enc_key);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    TPM2B_MAX_BUFFER encrypted_inner_integrity = TPM2B_EMPTY_INIT;
    TPMI_ALG_HASH name_alg = ctx.public.publicArea.nameAlg;
    result = tpm2_identity_util_calculate_inner_integrity(name_alg, &private_sensitive,
        &pubname, &ctx.enc_sensitive_key,
        &parent_pub->publicArea.parameters.rsaDetail.symmetric,
        &encrypted_inner_integrity);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(parent_pub->publicArea.nameAlg,
        &pubname, &encrypted_inner_integrity, &hmac_key, &enc_key,
        &parent_pub->publicArea.parameters.rsaDetail.symmetric,
        &encrypted_duplicate_sensitive, &outer_hmac);

    result = create_import_key_private_data(parent_pub->publicArea.nameAlg,
        &encrypted_duplicate_sensitive, &outer_hmac);
    if (!result) {
        rc = tool_rc_general_error;
        goto out;
    }

    /* symmetricAlg */
    ctx.sym_alg = parent_pub->publicArea.parameters.rsaDetail.symmetric;

out:
    if (free_ppub) {
        Esys_Free(parent_pub);
    }

    return rc;
}

static tool_rc process_input_tpm_import(void) {

    /*
     * Following is the reference from Table 41 of TPM Specifications Part 3 and
     * is used to construct a duplication wrapper on a tpm key
     *
     * 1. encryptionKey - Load(tpm-duplicate) -> `k` -> ctx.enc_sensitive_key
     * 2. objectPublic  - Load(tpm-duplicate) -> `u` -> ctx.public
     * 3. duplicate     - Load(tpm-duplicate) -> `i` -> ctx.duplicate
     * 4. inSymSeed     - Load(tpm-duplicate) -> `s` -> ctx.encrypted_seed
     * 5. symmetricAlg  - Read from parent objectPublic -> ctx.sym_alg
     */

    /* encryptionKey */
    if (ctx.input_enc_key_file) {
        ctx.enc_sensitive_key.size = 16;
        bool result = files_load_bytes_from_path(ctx.input_enc_key_file,
            ctx.enc_sensitive_key.buffer, &ctx.enc_sensitive_key.size);
        if (!result) {
            LOG_ERR("Failed to load symmetric encryption key\"%s\"",
                ctx.input_enc_key_file);
            return tool_rc_general_error;
        }
        if (ctx.enc_sensitive_key.size != 16) {
            LOG_ERR("Invalid AES key size, got %u bytes, expected 16",
                    ctx.enc_sensitive_key.size);
            return tool_rc_general_error;
        }

        /* symmetricAlg */
        ctx.sym_alg.algorithm = TPM2_ALG_AES;
        ctx.sym_alg.keyBits.aes = 128;
        ctx.sym_alg.mode.aes = TPM2_ALG_CFB;
    }

    /* duplicate or the to-be-imported-wrapped-key */
    bool result = files_load_private(ctx.input_key_file, &ctx.duplicate);
    if (!result) {
        LOG_ERR("Failed to load duplicate \"%s\"", ctx.input_key_file);
        return tool_rc_general_error;
    }

    /* inSymSeed */
    result = files_load_encrypted_seed(ctx.input_seed_file,
        &ctx.encrypted_seed);
    if (!result) {
        LOG_ERR("Failed to load encrypted seed \"%s\"", ctx.input_seed_file);
        return tool_rc_general_error;
    }

    /* objectPublic */
    result = files_load_public(ctx.public_key_file, &ctx.public);
    if (!result) {
        LOG_ERR(":( Failed to load public key \"%s\"", ctx.public_key_file);
        return tool_rc_general_error;
    }

    if (ctx.policy) {
        tool_rc rc = tpm2_policy_set_digest(ctx.policy,
                &ctx.public.publicArea.authPolicy);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    return tool_rc_success;
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
        ctx.parent.auth_str, &ctx.parent.object, false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid parent key authorization");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * tpm_import:  Import key that was generated with tpm2_duplicate.
     *              Load tss-public & tss-private.
     * ossl_import: Import key generated with ossl.
     *              Generate tss-public & tss-duplicate.
     */
    rc = ctx.import_tpm ?
        process_input_tpm_import() : process_input_ossl_import(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.parent.object.session,
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

    tool_rc rc = tool_rc_success;
    /* Check the tpm import specific options */
    if (ctx.import_tpm) {
        if (!ctx.input_seed_file) {
            LOG_ERR("Expected SymSeed to be specified via \"-s\","
                    " missing option.");
            rc = tool_rc_option_error;
        }

        if (ctx.key_auth_str) {
            LOG_ERR("Cannot specify key password when importing a TPM key.\n"
                    "use tpm2_changeauth after import");
            rc = tool_rc_option_error;
        }
    }

    /* Openssl specific option(s) */
    if (!ctx.import_tpm) {
        if (!ctx.object_alg) {
            LOG_ERR("Expected object type to be specified via \"-G\","
                    " missing option.");
            rc = tool_rc_option_error;
        }

        if (ctx.cp_hash_path) {
            LOG_WARN("CAUTION CpHash calculation includes parameters that"
                     "have a derived/random seed!");
        }
    }

    /* Common options */
    if (!ctx.input_key_file) {
        LOG_ERR("Expected to be imported key data to be specified via \"-i\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.public_key_file) {
        LOG_ERR("Expected output public file missing, specify \"-u\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.private_key_file) {
        LOG_ERR("Expected output private file missing, specify \"-r\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.parent.ctx_path) {
        LOG_ERR("Expected parent key to be specified via \"-C\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'p':
        ctx.key_auth_str = value;
        break;
    case 'G':
        ctx.object_alg = value;
        return true;
    case 'i':
        ctx.input_key_file = value;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'U':
        ctx.parent_key_public_file = value;
        break;
    case 'k':
        ctx.import_tpm = true;
        ctx.input_enc_key_file = value;
        break;
    case 'u':
        ctx.public_key_file = value;
        break;
    case 'r':
        ctx.private_key_file = value;
        break;
    case 'a':
        ctx.attrs = value;
        break;
    case 'g':
        ctx.name_alg = value;
        break;
    case 's':
        ctx.import_tpm = true;
        ctx.input_seed_file = value;
        break;
    case 'L':
        ctx.policy = value;
        break;
    case 0:
        ctx.passin = value;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 'R':
        ctx.autoflush = true;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "parent-auth",        required_argument, 0, 'P'},
      { "key-auth",           required_argument, 0, 'p'},
      { "key-algorithm",      required_argument, 0, 'G'},
      { "input",              required_argument, 0, 'i'},
      { "parent-context",     required_argument, 0, 'C'},
      { "parent-public",      required_argument, 0, 'U'},
      { "private",            required_argument, 0, 'r'},
      { "public",             required_argument, 0, 'u'},
      { "attributes",         required_argument, 0, 'a'},
      { "hash-algorithm",     required_argument, 0, 'g'},
      { "seed",               required_argument, 0, 's'},
      { "policy",             required_argument, 0, 'L'},
      { "encryption-key",     required_argument, 0, 'k'},
      { "passin",             required_argument, 0,  0 },
      { "cphash",             required_argument, 0,  1 },
      { "autoflush",          no_argument,       0, 'R' },
    };

    *opts = tpm2_options_new("P:p:G:i:C:U:u:r:a:g:s:L:k:R", ARRAY_LEN(topts),
        topts, on_option, 0, 0);

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
    rc = import(ectx);
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

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.parent.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("import", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
