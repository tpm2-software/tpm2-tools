//**********************************************************************;
// Copyright (c) 2017-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_kdfa.h"
#include "tpm2_errata.h"
#include "tpm2_openssl.h"
#include "tpm2_identity_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_import_ctx tpm_import_ctx;
struct tpm_import_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    char *input_key_file;
    char *public_key_file;
    char *private_key_file;
    char *parent_key_public_file;
    char *name_alg;
    char *attrs; /* The attributes to use */
    char *key_auth_str;
    char *parent_auth_str;
    char *auth_key_file; /* an optional auth string for the input key file for OSSL */
    char *input_seed_file;
    char *input_enc_key_file;
    char *policy;
    bool import_tpm; /* Any param that is exclusively used by import tpm object sets this flag */
    TPMI_ALG_PUBLIC key_type;
    const char *parent_ctx_arg;
};

static tpm_import_ctx ctx = {
    .key_type = TPM2_ALG_ERROR,
    .input_key_file = NULL,
    .auth.session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
};


static bool tpm2_readpublic(ESYS_CONTEXT *ectx, ESYS_TR handle,
                TPM2B_PUBLIC **public) {

    TSS2_RC rval = Esys_ReadPublic(ectx, handle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    public, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ReadPublic, rval);
        return false;
    }

    return true;
}

static bool create_name(TPM2B_PUBLIC *public, TPM2B_NAME *pubname) {

    /*
     * A TPM2B_NAME is the name of the algorithm, followed by the hash.
     * Calculate the name by:
     * 1. Marshaling the name algorithm
     * 2. Marshaling the TPMT_PUBLIC past the name algorithm from step 1.
     * 3. Hash the TPMT_PUBLIC portion in marshaled data.
     */

    TPMI_ALG_HASH name_alg = public->publicArea.nameAlg;

    // Step 1 - set beginning of name to hash alg
    size_t hash_offset = 0;
    Tss2_MU_UINT16_Marshal(name_alg, pubname->name,
            pubname->size, &hash_offset);

    // Step 2 - marshal TPMTP
    TPMT_PUBLIC marshaled_tpmt;
    size_t tpmt_marshalled_size = 0;
    Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea,
            (uint8_t *)&marshaled_tpmt, sizeof(public->publicArea),
        &tpmt_marshalled_size);

    // Step 3 - Hash the data into name just past the alg type.
    digester d = tpm2_openssl_halg_to_digester(name_alg);
    if (!d) {
        return false;
    }

    d((const unsigned char *)&marshaled_tpmt,
            tpmt_marshalled_size,
            pubname->name + 2);


    //Set the name size, UINT16 followed by HASH
    UINT16 hash_size = tpm2_alg_util_get_hash_size(name_alg);
    pubname->size = hash_size + 2;

    return true;
}

static void create_import_key_private_data(
        TPM2B_PRIVATE *private,
        TPMI_ALG_HASH parent_name_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac) {

    //UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);

    private->size = sizeof(uint16_t) + parent_hash_size
            + encrypted_duplicate_sensitive->size;
    size_t hmac_size_offset = 0;
    Tss2_MU_UINT16_Marshal(parent_hash_size, private->buffer,
            sizeof(uint16_t), &hmac_size_offset);
    memcpy(private->buffer + hmac_size_offset,
            outer_hmac->buffer, parent_hash_size);
    memcpy(
            private->buffer + hmac_size_offset
                    + parent_hash_size,
            encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size);
}

static bool do_import(ESYS_CONTEXT *ectx,
        ESYS_TR phandle,
        TPM2B_ENCRYPTED_SECRET *encrypted_seed,
        TPM2B_DATA *enc_sensitive_key,
        TPM2B_PRIVATE *private, TPM2B_PUBLIC *public,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_PRIVATE **imported_private) {

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, phandle,
                            &ctx.auth.session_data, ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle for phandle");
        return false;
    }

    TSS2_RC rval = Esys_Import(ectx, phandle,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                    enc_sensitive_key,
                    public, private, encrypted_seed, sym_alg,
                    imported_private);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Import, rval);
        return false;
    }

    return true;
}

static bool key_import(
        ESYS_CONTEXT *ectx,
        TPM2B_PUBLIC *parent_pub,
        ESYS_TR phandle,
        TPM2B_SENSITIVE *privkey,
        TPM2B_PUBLIC *pubkey,
        TPM2B_PRIVATE **imported_private) {

    TPMI_ALG_HASH name_alg = pubkey->publicArea.nameAlg;

    TPM2B_DIGEST *seed = &privkey->sensitiveArea.seedValue;

    /*
     * Create the protection encryption key that gets encrypted with the parents public key.
     */
    TPM2B_DATA enc_sensitive_key = {
        .size = parent_pub->publicArea.parameters.rsaDetail.symmetric.keyBits.sym / 8
    };
    memset(enc_sensitive_key.buffer, 0xFF, enc_sensitive_key.size);

    /*
     * Calculate the object name.
     */
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    bool res = create_name(pubkey, &pubname);
    if (!res) {
        return false;
    }

    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            parent_pub,
            &pubname,
            seed,
            &hmac_key,
            &enc_key);

    TPM2B_MAX_BUFFER encrypted_inner_integrity = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_inner_integrity(name_alg, privkey, &pubname, &enc_sensitive_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_inner_integrity);

    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(
            parent_pub->publicArea.nameAlg,
            &pubname,
            &encrypted_inner_integrity,
            &hmac_key,
            &enc_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_duplicate_sensitive,
            &outer_hmac);

    TPM2B_PRIVATE private = TPM2B_EMPTY_INIT;
    create_import_key_private_data(&private,
            parent_pub->publicArea.nameAlg,
            &encrypted_duplicate_sensitive, &outer_hmac);

    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;
    unsigned char label[10] = { 'D', 'U', 'P', 'L', 'I', 'C', 'A', 'T', 'E', 0 };
    res = tpm2_identity_util_encrypt_seed_with_public_key(seed,
            parent_pub,
            label, 10,
            &encrypted_seed);
    if (!res) {
        LOG_ERR("Failed Seed Encryption\n");
        return false;
    }

    TPMT_SYM_DEF_OBJECT *sym_alg = &parent_pub->publicArea.parameters.rsaDetail.symmetric;

    return do_import(
            ectx,
            phandle,
            &encrypted_seed, &enc_sensitive_key,
            &private, pubkey,
            sym_alg,
            imported_private);
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'P':
        ctx.parent_auth_str = value;
        break;
    case 'p':
        ctx.key_auth_str = value;
    break;
    case 'G':
        ctx.key_type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_asymmetric
                |tpm2_alg_util_flags_symmetric);
        if (ctx.key_type == TPM2_ALG_ERROR) {
            LOG_ERR("Unsupported key type");
            return false;
        }
        return true;
    case 'i':
        ctx.input_key_file = value;
        break;
    case 'C':
        ctx.parent_ctx_arg = value;
        break;
    case 'K':
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
    case 'b':
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
        ctx.import_tpm = true;
        ctx.policy = value;
        break;
    case 0:
        ctx.auth_key_file = value;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth-parent",        required_argument, NULL, 'P'},
      { "auth-key",           required_argument, NULL, 'p'},
      { "algorithm",          required_argument, NULL, 'G'},
      { "in-file",            required_argument, NULL, 'i'},
      { "parent-key",         required_argument, NULL, 'C'},
      { "parent-pubkey",      required_argument, NULL, 'K'},
      { "privkey",            required_argument, NULL, 'r'},
      { "pubkey",             required_argument, NULL, 'u'},
      { "object-attributes",  required_argument, NULL, 'b'},
      { "halg",               required_argument, NULL, 'g'},
      { "seed",               required_argument, NULL, 's'},
      { "policy-file",        required_argument, NULL, 'L'},
      { "sym-alg-file",       required_argument, NULL, 'k'},
      { "passin",             required_argument, NULL,  0 },
    };

    *opts = tpm2_options_new("P:p:G:i:C:K:u:r:b:g:s:L:k:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

/**
 * Check all options and report as many errors as possible via LOG_ERR.
 * @return
 *  0 on success, -1 on failure.
 */
static int check_options(void) {

    int rc = 0;

    /* Check the tpm import specific options */
    if(ctx.import_tpm) {

        if(!ctx.policy) {
            LOG_ERR("Expected imported key policy to be specified via \"-L\","
                    " missing option.");
            rc = -1;
        }

        if(!ctx.input_seed_file) {
            LOG_ERR("Expected SymSeed to be specified via \"-s\","
                    " missing option.");
            rc = -1;
        }

        /* If a key file is specified we choose aes else null
        for symmetricAlgdefinition */
        if(!ctx.input_enc_key_file) {
            ctx.key_type = TPM2_ALG_NULL;
        } else {
            ctx.key_type = TPM2_ALG_AES;
        }

    } else {    /* Openssl specific option(s) */

        if (!ctx.key_type) {
            LOG_ERR("Expected key type to be specified via \"-G\","
                    " missing option.");
            rc = -1;
        }
    }

    /* Common options */
    if (!ctx.input_key_file) {
        LOG_ERR("Expected to be imported key data to be specified via \"-i\","
                " missing option.");
        rc = -1;
    }

    if (!ctx.public_key_file) {
        LOG_ERR("Expected output public file missing, specify \"-u\","
                " missing option.");
        rc = -1;
    }

    if (!ctx.private_key_file) {
        LOG_ERR("Expected output private file missing, specify \"-r\","
                " missing option.");
        rc = -1;
    }

    if (!ctx.parent_ctx_arg) {
        LOG_ERR("Expected parent key to be specified via \"-C\","
                " missing option.");
        rc = -1;
    }

    return rc;
}

static int openssl_import(ESYS_CONTEXT *ectx) {

    bool result;
    bool free_ppub = false;

    tpm2_loaded_object parent_ctx;
    int rc = 1;

    /*
     * Load the parent public file, or read it from the TPM if not specified.
     * We need this information for encrypting the protection seed.
     */
    result = tpm2_util_object_load(ectx, ctx.parent_ctx_arg,
                                &parent_ctx);
    if (!result) {
      goto out;
    }

    TPM2B_PUBLIC ppub = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *parent_pub = NULL;
    if (ctx.parent_key_public_file) {
        result = files_load_public(ctx.parent_key_public_file, &ppub);
        parent_pub = &ppub;
    } else {
        result = tpm2_readpublic(ectx, parent_ctx.tr_handle, &parent_pub);
        free_ppub = true;
    }
    if (!result) {
        LOG_ERR("Failed loading parent key public.");
        return false;
    }

    TPM2B_SENSITIVE private = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = {
        .size = 0,
        .publicArea = {
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT
        },
    };

    if (ctx.name_alg) {
        TPMI_ALG_HASH alg = tpm2_alg_util_from_optarg(ctx.name_alg,
                tpm2_alg_util_flags_hash);
        if (alg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid name hashing algorithm, got\"%s\"", ctx.name_alg);
            return false;
        }
        public.publicArea.nameAlg = alg;
    } else {
        /*
         * use the parent name algorithm if not specified
         */
        public.publicArea.nameAlg =
                parent_pub->publicArea.nameAlg;
    }

    /*
     * The TPM Requires that the name algorithm for the child be less than the name
     * algorithm of the parent when the parent's scheme is NULL.
     *
     * This check can be seen in the simulator at:
     *   - File: CryptUtil.c
     *   - Func: CryptSecretDecrypt()
     *   - Line: 2019
     *   - Decription: Limits the size of the hash algorithm to less then the parent's name-alg when scheme is NULL.
     */
    UINT16 hash_size = tpm2_alg_util_get_hash_size(public.publicArea.nameAlg);
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_pub->publicArea.nameAlg);
    if (hash_size > parent_hash_size) {
        LOG_WARN("Hash selected is larger then parent hash size, coercing to parent hash algorithm: %s",
                tpm2_alg_util_algtostr(parent_pub->publicArea.nameAlg, tpm2_alg_util_flags_hash));
        public.publicArea.nameAlg =
                    parent_pub->publicArea.nameAlg;
    }

    /*
     * Set the object attributes if specified, overwriting the defaults, but hooking the errata
     * fixups.
     */
    if (ctx.attrs) {
        TPMA_OBJECT *obj_attrs = &public.publicArea.objectAttributes;
        result = tpm2_util_string_to_uint32(ctx.attrs, obj_attrs);
        if (!result) {
            LOG_ERR("Invalid object attribute, got\"%s\"", ctx.attrs);
            return false;
        }

        tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                          &public.publicArea.objectAttributes);
    }

    if (ctx.key_auth_str) {
        TPMS_AUTH_COMMAND tmp;
        result = tpm2_auth_util_from_optarg(ectx, ctx.key_auth_str, &tmp, NULL);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.key_auth_str);
            return false;
        }
        private.sensitiveArea.authValue = tmp.hmac;
    }

    if (ctx.parent_auth_str) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.parent_auth_str,
            &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
            return false;
        }
    }
    /*
     * Populate all the private and public data fields we can based on the key type and the PEM files read in.
     */
    tpm2_openssl_load_rc status = tpm2_openssl_load_private(ctx.input_key_file, ctx.auth_key_file,
            ctx.key_type, &public, &private);
    if (status == lprc_error) {
        goto out;
    }

    if (!tpm2_openssl_did_load_public(status)) {
        LOG_ERR("Did not find public key information in file: \"%s\"", ctx.input_key_file);
        goto out;
    }

    TPM2B_PRIVATE *imported_private = NULL;
    result = key_import(ectx, parent_pub, parent_ctx.tr_handle,
                &private, &public, &imported_private);
    if (!result) {
        goto keyout;
    }

    /*
     * Save the public and imported_private structure to disk
     */
    bool res = files_save_public(&public, ctx.public_key_file);
    if(!res) {
        goto keyout;
    }

    res = files_save_private(imported_private, ctx.private_key_file);
    if (!res) {
        goto keyout;
    }

    /*
     * Output the stats on the created object on Success.
     */
    tpm2_util_public_to_yaml(&public, NULL);

    rc = 0;
keyout:
    free(imported_private);
out:
    if (free_ppub) {
        free(parent_pub);
    }
    return rc;
}

static bool set_key_algorithm(TPMI_ALG_PUBLIC alg, TPMT_SYM_DEF_OBJECT * obj) {
    bool result = true;
    switch (alg) {
    case TPM2_ALG_AES :
        obj->algorithm = TPM2_ALG_AES;
        obj->keyBits.aes = 128;
        obj->mode.aes = TPM2_ALG_CFB;
        break;
    case TPM2_ALG_NULL :
        obj->algorithm = TPM2_ALG_NULL;
        break;
    default:
        LOG_ERR("The algorithm type input(0x%x) is not supported!", alg);
        result = false;
        break;
    }
    return result;
}

static int tpm_import(ESYS_CONTEXT *ectx) {
    bool result;
    TPM2B_DATA enc_key = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_PRIVATE duplicate;
    TPM2B_ENCRYPTED_SECRET encrypted_seed;
    TPM2B_PRIVATE *imported_private;
    tpm2_loaded_object parent_object_context;
    TPMT_SYM_DEF_OBJECT sym_alg;

    result = tpm2_util_object_load(ectx, ctx.parent_ctx_arg,
                                &parent_object_context);
    if (!result) {
      return 1;
    }

    if (ctx.parent_auth_str) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.parent_auth_str,
            &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
            return 1;
        }
    }

    result = set_key_algorithm(ctx.key_type, &sym_alg);
    if(!result) {
        return 1;
    }

    /* Symmetric key */
    if(ctx.input_enc_key_file) {
        enc_key.size = 16;
        result = files_load_bytes_from_path(ctx.input_enc_key_file, enc_key.buffer, &enc_key.size);
        if(!result) {
            LOG_ERR("Failed to load symmetric encryption key\"%s\"", ctx.input_enc_key_file);
            return 1;
        }
        if(enc_key.size != 16) {
            LOG_ERR("Invalid AES key size, got %u bytes, expected 16", enc_key.size);
            return 1;
        }
    }

    /* Private key */
    result = files_load_private(ctx.input_key_file, &duplicate);
    if(!result) {
        LOG_ERR("Failed to load duplicate \"%s\"", ctx.input_key_file);
        return 1;
    }

    /* Encrypted seed */
    result = files_load_encrypted_seed(ctx.input_seed_file, &encrypted_seed);
    if(!result) {
        LOG_ERR("Failed to load encrypted seed \"%s\"", ctx.input_seed_file);
        return 1;
    }

    /* Public key */
    result = files_load_public(ctx.public_key_file, &public);
    if(!result) {
        LOG_ERR(":( Failed to load public key \"%s\"", ctx.public_key_file);
        return 1;
    }

    public.publicArea.authPolicy.size = sizeof(public.publicArea.authPolicy.buffer);
    result = files_load_bytes_from_path(ctx.policy,
                public.publicArea.authPolicy.buffer, &public.publicArea.authPolicy.size);
    if (!result) {
        return 1;
    }

    result = do_import(
            ectx,
            parent_object_context.tr_handle,
            &encrypted_seed, 
            &enc_key,
            &duplicate, 
            &public,
            &sym_alg,
            &imported_private);

    if (!result) {
        return 1;
    }

    result = files_save_private(imported_private, ctx.private_key_file);
    free(imported_private);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.private_key_file);
        return 1;
    }


    result = tpm2_session_save(ectx, ctx.auth.session, NULL);

    return result ? 0 : 1;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    int rc;
    UNUSED(flags);

    rc = check_options();
    if (rc) {
        return 1;
    }

    if(!ctx.import_tpm) {
        return openssl_import(ectx);
    }
    return tpm_import(ectx);
}

