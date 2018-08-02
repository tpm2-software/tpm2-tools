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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <limits.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm_kdfa.h"
#include "tpm2_errata.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_import_ctx tpm_import_ctx;
struct tpm_import_ctx {
    char *input_key_file;
    char *import_key_public_file;
    char *import_key_private_file;
    char *parent_key_public_file;

    TPMI_ALG_PUBLIC key_type;
    const char *parent_ctx_arg;

    UINT32 objectAttributes;
    TPMI_ALG_HASH name_alg;
};

static tpm_import_ctx ctx = { 
    .key_type = TPM2_ALG_ERROR,
    .input_key_file = NULL,
    .name_alg = TPM2_ALG_ERROR
};

#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER) /* OpenSSL 1.1.0 */
static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {

    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL)) {
        return 0;
    }

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }

    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }

    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
#endif

static bool tpm2_readpublic(TSS2_SYS_CONTEXT *sapi, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public) {

    TSS2L_SYS_AUTH_RESPONSE sessions_out_data;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ReadPublic(sapi, handle, NULL,
            public, &name, &qualified_name, &sessions_out_data));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ReadPublic, rval);
        return false;
    }

    return true;
}

static bool encrypt_seed_with_tpm2_rsa_public_key(TPM2B_DATA *protection_seed,
        TPM2B_PUBLIC *parent_pub,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool rval = false;
    RSA *rsa = NULL;

    // Public modulus
    TPMI_RSA_KEY_BITS mod_size_bits = parent_pub->publicArea.parameters.rsaDetail.keyBits;
    UINT16 mod_size = mod_size_bits / 8;
    TPM2B *pub_key_val = (TPM2B *)&parent_pub->publicArea.unique.rsa;
    unsigned char *pub_modulus = malloc(mod_size);
    if (pub_modulus == NULL) {
        LOG_ERR("Failed to allocate memory to store public key's modulus.");
        return false;
    }
    memcpy(pub_modulus, pub_key_val->buffer, mod_size);

    TPMI_ALG_HASH parent_name_alg = parent_pub->publicArea.nameAlg;

    /*
     * This is the biggest buffer value, so it should always be sufficient.
     */
    unsigned char encoded[TPM2_MAX_DIGEST_BUFFER];
    unsigned char label[10] = { 'D', 'U', 'P', 'L', 'I', 'C', 'A', 'T', 'E', 0 };
    int return_code = RSA_padding_add_PKCS1_OAEP_mgf1(encoded,
            mod_size, protection_seed->buffer, protection_seed->size, label, 10,
            tpm2_openssl_halg_from_tpmhalg(parent_name_alg), NULL);
    if (return_code != 1) {
        LOG_ERR("Failed RSA_padding_add_PKCS1_OAEP_mgf1\n");
        goto error;
    }
    BIGNUM* bne = BN_new();
    if (!bne) {
        LOG_ERR("BN_new for bne failed\n");
        goto error;
    }
    return_code = BN_set_word(bne, RSA_F4);
    if (return_code != 1) {
        LOG_ERR("BN_set_word failed\n");
        BN_free(bne);
        goto error;
    }
    rsa = RSA_new();
    if (!rsa) {
        LOG_ERR("RSA_new failed\n");
        BN_free(bne);
        goto error;
    }
    return_code = RSA_generate_key_ex(rsa, mod_size_bits, bne, NULL);
    BN_free(bne);
    if (return_code != 1) {
        LOG_ERR("RSA_generate_key_ex failed\n");
        goto error;
    }
    BIGNUM *n = BN_bin2bn(pub_modulus, mod_size, NULL);
    if (n == NULL) {
        LOG_ERR("BN_bin2bn failed\n");
        goto error;
    }
    if (!RSA_set0_key(rsa, n, NULL, NULL)) {
        LOG_ERR("RSA_set0_key failed\n");
        BN_free(n);
        goto error;
    }
    // Encrypting
    encrypted_protection_seed->size = mod_size;
    return_code = RSA_public_encrypt(mod_size, encoded,
            encrypted_protection_seed->secret, rsa, RSA_NO_PADDING);
    if (return_code < 0) {
        LOG_ERR("Failed RSA_public_encrypt\n");
        goto error;
    }

    rval = true;

error:
    free(pub_modulus);
    RSA_free(rsa);
    return rval;
}

static const EVP_CIPHER *tpm_alg_to_ossl(TPMT_SYM_DEF_OBJECT *sym) {

    switch(sym->algorithm) {
        case TPM2_ALG_AES: {
            switch (sym->keyBits.aes) {
            case 128:
                return EVP_aes_128_cfb();
            case 256:
                return EVP_aes_256_cfb();
            /* no default */
            }
        }
        /* no default */
    }

    LOG_ERR("Unsupported parent key symmetric parameters");

    return NULL;
}

bool aes_encrypt_buffers(TPMT_SYM_DEF_OBJECT *sym, uint8_t *encryption_key,
        uint8_t *buf1, size_t buf1_len,
        uint8_t *buf2, size_t buf2_len,
        TPM2B_MAX_BUFFER *cipher_text) {

    bool result = false;

    unsigned offset = 0;
    size_t total_len = buf1_len + buf2_len;

    if (total_len > sizeof(cipher_text->buffer)) {
        LOG_ERR("Plaintext too big, got %zu, expected less then %zu",
                total_len, sizeof(cipher_text->buffer));
        return false;
    }

    const EVP_CIPHER *cipher = tpm_alg_to_ossl(sym);
    if (!cipher) {
        return false;
    }

    const unsigned char iv[512] = { 0 };

    if (((unsigned long)EVP_CIPHER_iv_length(cipher)) > sizeof(iv)) {
        LOG_ERR("IV size is bigger then IV buffer size");
        return false;
    }

    EVP_CIPHER_CTX *ctx = tpm2_openssl_cipher_new();

    int rc = EVP_EncryptInit_ex(ctx, cipher, NULL, encryption_key, iv);
    if (!rc) {
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t *bufs[2] = {
        buf1,
        buf2
    };

    size_t lens[ARRAY_LEN(bufs)] = {
        buf1_len,
        buf2_len
    };

    unsigned i;
    for (i=0; i < ARRAY_LEN(bufs); i++) {

        uint8_t *b = bufs[i];
        size_t l = lens[i];

        if (!b) {
            continue;
        }

        int output_len = total_len - offset;

        rc = EVP_EncryptUpdate(ctx, &cipher_text->buffer[offset], &output_len - offset, b, l);
        if (!rc) {
            LOG_ERR("Encrypt failed");
            goto out;
        }

        offset += l;
    }

    int tmp_len = 0;
    rc = EVP_EncryptFinal_ex(ctx, NULL, &tmp_len);
    if (!rc) {
        LOG_ERR("Encrypt failed");
        goto out;
    }

    cipher_text->size = total_len;

    result = true;

out:
    tpm2_openssl_cipher_free(ctx);

    return result;
}

static void hmac_outer_integrity(
        TPMI_ALG_HASH parent_name_alg,
        uint8_t *buffer1, uint16_t buffer1_size,
        uint8_t *buffer2, uint16_t buffer2_size, uint8_t *hmac_key,
        TPM2B_DIGEST *outer_integrity_hmac) {

    uint8_t to_hmac_buffer[TPM2_MAX_DIGEST_BUFFER];
    memcpy(to_hmac_buffer, buffer1, buffer1_size);
    memcpy(to_hmac_buffer + buffer1_size, buffer2, buffer2_size);
    uint32_t size = 0;

    UINT16 hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);

    HMAC(tpm2_openssl_halg_from_tpmhalg(parent_name_alg), hmac_key, hash_size, to_hmac_buffer,
            buffer1_size + buffer2_size, outer_integrity_hmac->buffer, &size);
    outer_integrity_hmac->size = size;
}

static void create_random_seed_and_sensitive_enc_key(TPM2B_DATA *protection_seed, TPM2B_DATA *enc_sensitive_key) {

    protection_seed->size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    RAND_bytes(protection_seed->buffer, protection_seed->size);

    RAND_bytes(enc_sensitive_key->buffer, enc_sensitive_key->size);
}

typedef unsigned char *(*digester)(const unsigned char *d, size_t n, unsigned char *md);

static digester halg_to_digester(TPMI_ALG_HASH halg) {

    switch(halg) {
    case TPM2_ALG_SHA1:
        return SHA1;
    case TPM2_ALG_SHA256:
        return SHA256;
    case TPM2_ALG_SHA384:
        return SHA384;
    case TPM2_ALG_SHA512:
        return SHA512;
    /* no default */
    }

    return NULL;
}

static bool calc_sensitive_unique_data(TPM2B_MAX_BUFFER *key, TPM2B_DATA *protection_seed, TPM2B_DIGEST *unique_data) {

    bool result = false;

    uint8_t *concatenated_seed_unique = malloc(protection_seed->size +
                                            key->size);
    if (!concatenated_seed_unique) {
        LOG_ERR("oom");
        return false;
    } 

    memcpy(concatenated_seed_unique, protection_seed->buffer,
            protection_seed->size);

    memcpy(concatenated_seed_unique + protection_seed->size, key->buffer,
        key->size);

    digester d = halg_to_digester(ctx.name_alg);
    if (!d) {
        goto out;
    }

    unique_data->size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    d(concatenated_seed_unique, protection_seed->size + key->size,
        unique_data->buffer);

    result = true;

out:
    free(concatenated_seed_unique);

    return result;
}

static inline void  IMPORT_KEY_SYM_PUBLIC_AREA(TPM2B_PUBLIC *p) {
    p->publicArea.type = TPM2_ALG_SYMCIPHER;
    p->publicArea.nameAlg = ctx.name_alg;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
    p->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    p->publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    p->publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_FIXEDTPM;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_FIXEDPARENT;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
    p->publicArea.authPolicy.size = 0;
    p->publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
    p->publicArea.parameters.symDetail.sym.keyBits.sym = 128;
    p->publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
    p->publicArea.unique.sym.size = tpm2_alg_util_get_hash_size(ctx.name_alg);
}

static inline void IMPORT_KEY_RSA2K_PUBLIC_AREA(TPM2B_MAX_BUFFER *pubkey, TPM2B_PUBLIC *p) {
    p->publicArea.type = TPM2_ALG_RSA;
    p->publicArea.nameAlg = ctx.name_alg;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
    p->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    p->publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    p->publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_FIXEDTPM;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_FIXEDPARENT;
    p->publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
    p->publicArea.authPolicy.size = 0;
    p->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    p->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    p->publicArea.parameters.rsaDetail.keyBits = pubkey->size * 8;
    p->publicArea.parameters.rsaDetail.exponent = 0x0;
    p->publicArea.unique.rsa.size = pubkey->size;
}

static bool create_import_key_public_data_and_name(
        TPM2B_MAX_BUFFER *pubkey,
        TPM2B_PUBLIC *public,
        TPM2B_NAME *pubname,
        TPM2B_DIGEST *sym) {

    switch (ctx.key_type) {
        case TPM2_ALG_AES:
            IMPORT_KEY_SYM_PUBLIC_AREA(public);
            public->publicArea.unique.sym = *sym;
            break;
        case TPM2_ALG_RSA:
            IMPORT_KEY_RSA2K_PUBLIC_AREA(pubkey, public);
            memcpy(public->publicArea.unique.rsa.buffer,
                pubkey->buffer, pubkey->size);
            break;
    }

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &public->publicArea.objectAttributes);

    if (ctx.objectAttributes) {
        public->publicArea.objectAttributes = ctx.objectAttributes;
    }

    tpm2_util_tpma_object_to_yaml(public->publicArea.objectAttributes, NULL);

    /*
     * A TPM2B_NAME is the name of the algorithm, followed by the hash.
     * Calculate the name by:
     * 1. Marshaling the name algorithm
     * 2. Marshaling the TPMT_PUBLIC past the name algorithm from step 1.
     * 3. Hash the TPMT_PUBLIC portion in marshaled data.
     */

    // Step 1 - set beginning of name to hash alg
    size_t hash_offset = 0;
    Tss2_MU_UINT16_Marshal(ctx.name_alg, pubname->name,
            pubname->size, &hash_offset);

    // Step 2 - marshal TPMTP
    TPMT_PUBLIC marshaled_tpmt;
    size_t tpmt_marshalled_size = 0;
    Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea,
            (uint8_t *)&marshaled_tpmt, sizeof(public->publicArea),
        &tpmt_marshalled_size);

    // Step 3 - Hash the data into name just past the alg type.
    digester d = halg_to_digester(ctx.name_alg);
    if (!d) {
        return false;
    }

    d((const unsigned char *)&marshaled_tpmt,
            tpmt_marshalled_size,
            pubname->name + 2);


    //Set the name size, UINT16 followed by HASH
    UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    pubname->size = hash_size + 2;

    return true;
}

static void create_import_key_sensitive_data(TPM2B_SENSITIVE *sensitive, TPM2B_MAX_BUFFER *key,
        TPM2B_DATA *protection_seed) {

    sensitive->sensitiveArea.authValue.size = 0;
    sensitive->sensitiveArea.seedValue.size =
            tpm2_alg_util_get_hash_size(ctx.name_alg);

    memcpy(sensitive->sensitiveArea.seedValue.buffer,
            protection_seed->buffer, sensitive->sensitiveArea.seedValue.size);

    switch (ctx.key_type) {
        case TPM2_ALG_AES:
            sensitive->sensitiveArea.sensitiveType =
                TPM2_ALG_SYMCIPHER;
            sensitive->sensitiveArea.sensitive.sym.size =
                key->size;
            memcpy(sensitive->sensitiveArea.sensitive.sym.buffer,
                key->buffer, key->size);
            break;
        case TPM2_ALG_RSA:
            sensitive->sensitiveArea.sensitiveType =
                TPM2_ALG_RSA;
            sensitive->sensitiveArea.sensitive.rsa.size =
                key->size;
            memcpy(sensitive->sensitiveArea.sensitive.rsa.buffer,
                key->buffer, key->size);
            break;
    }
}

static TPM2_KEY_BITS get_pub_asym_key_bits(TPM2B_PUBLIC *public) {

    TPMU_PUBLIC_PARMS *p = &public->publicArea.parameters;
    switch(public->publicArea.type) {
    case TPM2_ALG_ECC:
        /* fall-thru */
    case TPM2_ALG_RSA:
        return p->asymDetail.symmetric.keyBits.sym;
    /* no default */
    }

    return 0;
}

static bool calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        TPM2B_PUBLIC *parent_pub,
        TPM2B_NAME *pubname,
        TPM2B_DATA *protection_seed,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key) {

    TPM2B null_2b = { .size = 0 };

    TPMI_ALG_HASH parent_alg = parent_pub->publicArea.nameAlg;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_alg);

    TSS2_RC rval = tpm_kdfa(parent_alg, (TPM2B *)protection_seed, "INTEGRITY",
            &null_2b, &null_2b, parent_hash_size * 8, protection_hmac_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_KEY_BITS pub_key_bits = get_pub_asym_key_bits(parent_pub);

    rval = tpm_kdfa(parent_alg, (TPM2B *)protection_seed, "STORAGE",
            (TPM2B *)pubname, &null_2b, pub_key_bits,
            protection_enc_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    return true;
}

static void calculate_inner_integrity(TPM2B_SENSITIVE *sensitive, TPM2B_NAME *pubname, TPM2B_DATA *enc_sensitive_key,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_inner_integrity) {

    //Marshal sensitive area
    uint8_t buffer_marshalled_sensitiveArea[TPM2_MAX_DIGEST_BUFFER] = { 0 };
    size_t marshalled_sensitive_size = 0;
    Tss2_MU_TPMT_SENSITIVE_Marshal(&sensitive->sensitiveArea,
            buffer_marshalled_sensitiveArea + sizeof(uint16_t), TPM2_MAX_DIGEST_BUFFER,
            &marshalled_sensitive_size);
    size_t marshalled_sensitive_size_info = 0;
    Tss2_MU_UINT16_Marshal(marshalled_sensitive_size, buffer_marshalled_sensitiveArea,
            sizeof(uint16_t), &marshalled_sensitive_size_info);

    //concatenate NAME
    memcpy(
            buffer_marshalled_sensitiveArea + marshalled_sensitive_size
                    + marshalled_sensitive_size_info,
            pubname->name,
            pubname->size);

    //Digest marshalled-sensitive || name
    uint8_t *marshalled_sensitive_and_name_digest =
            buffer_marshalled_sensitiveArea + marshalled_sensitive_size
                    + marshalled_sensitive_size_info
                    + pubname->size;
    size_t digest_size_info = 0;
    UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    Tss2_MU_UINT16_Marshal(hash_size, marshalled_sensitive_and_name_digest,
            sizeof(uint16_t), &digest_size_info);

    digester d = halg_to_digester(ctx.name_alg);
    d(buffer_marshalled_sensitiveArea,
            marshalled_sensitive_size_info + marshalled_sensitive_size
                    + pubname->size,
            marshalled_sensitive_and_name_digest + digest_size_info);

    //Inner integrity
    encrypted_inner_integrity->size = marshalled_sensitive_size_info
            + marshalled_sensitive_size + pubname->size;

    aes_encrypt_buffers(
            sym_alg,
            enc_sensitive_key->buffer,
            marshalled_sensitive_and_name_digest, hash_size + digest_size_info,
            buffer_marshalled_sensitiveArea, marshalled_sensitive_size_info + marshalled_sensitive_size,
            encrypted_inner_integrity);
}

static void calculate_outer_integrity(
        TPMI_ALG_HASH parent_name_alg,
        TPM2B_NAME *pubname,
        TPM2B_MAX_BUFFER *encrypted_inner_integrity,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_DIGEST *outer_hmac) {

    //Calculate dupSensitive
    encrypted_duplicate_sensitive->size =
            encrypted_inner_integrity->size;

    aes_encrypt_buffers(
            sym_alg,
            protection_enc_key->buffer,
            encrypted_inner_integrity->buffer,
            encrypted_inner_integrity->size,
            NULL, 0,
            encrypted_duplicate_sensitive);
    //Calculate outerHMAC
    hmac_outer_integrity(
            parent_name_alg,
            encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size,
            pubname->name,
            pubname->size, protection_hmac_key->buffer,
            outer_hmac);
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

static bool import_external_key_and_save_public_private_data(TSS2_SYS_CONTEXT *sapi_context,
        TPM2_HANDLE phandle,
        TPM2B_ENCRYPTED_SECRET *encrypted_seed,
        TPM2B_DATA *enc_sensitive_key,
        TPM2B_PRIVATE *private, TPM2B_PUBLIC *public,
        TPMT_SYM_DEF_OBJECT *sym_alg) {

    TSS2L_SYS_AUTH_COMMAND npsessionsData =
            TSS2L_SYS_AUTH_COMMAND_INIT(1, {TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW)});

    TSS2L_SYS_AUTH_RESPONSE npsessionsDataOut;

    TPM2B_PRIVATE importPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Import(sapi_context, phandle,
            &npsessionsData, enc_sensitive_key, public,
            private, encrypted_seed, sym_alg,
            &importPrivate, &npsessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Import, rval);
        return false;
    }

    bool res = files_save_public(public, ctx.import_key_public_file);
    if(!res) {
        return false;
    }

    res = files_save_private(&importPrivate, ctx.import_key_private_file);
    if (!res) {
        return false;
    }

    return true;
}

static bool key_import(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE phandle, TPM2B_MAX_BUFFER *privkey, TPM2B_MAX_BUFFER *pubkey) {

    TPM2B_PUBLIC parent_pub = TPM2B_EMPTY_INIT;

    /*
     * Load the parent public, either via ascertained file or readpublic.
     */
    bool res = ctx.parent_key_public_file ?
            files_load_public(ctx.parent_key_public_file, &parent_pub) :
            tpm2_readpublic(sapi_context, phandle, &parent_pub);
    if (!res) {
        LOG_ERR("Failed loading parent key public.");
        return false;
    }

    if (ctx.name_alg == TPM2_ALG_ERROR) {
        ctx.name_alg = parent_pub.publicArea.nameAlg;
    } else if (parent_pub.publicArea.parameters.rsaDetail.scheme.scheme == TPM2_ALG_NULL){
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
        UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.name_alg);
        UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_pub.publicArea.nameAlg);
        if (hash_size > parent_hash_size) {
            LOG_WARN("Hash selected is larger then parent hash size, coercing to parent hash algorithm: %s",
                    tpm2_alg_util_algtostr(parent_pub.publicArea.nameAlg, tpm2_alg_util_flags_hash));
            ctx.name_alg = parent_pub.publicArea.nameAlg;
        }
    }

    TPM2B_DATA protection_seed = TPM2B_EMPTY_INIT;


    TPM2B_DATA enc_sensitive_key = {
        .size = parent_pub.publicArea.parameters.rsaDetail.symmetric.keyBits.sym / 8
    };

    create_random_seed_and_sensitive_enc_key(&protection_seed, &enc_sensitive_key);

    TPM2B_DIGEST sym = TPM2B_EMPTY_INIT;
    if (ctx.key_type == TPM2_ALG_AES) {
        res = calc_sensitive_unique_data(privkey, &protection_seed, &sym);
        if (!res) {
            return false;
        }
    }

    TPM2B_PRIVATE private = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    res = create_import_key_public_data_and_name(pubkey, &public, &pubname, &sym);
    if (!res) {
        return false;
    }

    TPM2B_SENSITIVE sensitive = TPM2B_EMPTY_INIT;
    create_import_key_sensitive_data(&sensitive, privkey, &protection_seed);

    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            &parent_pub,
            &pubname,
            &protection_seed,
            &hmac_key,
            &enc_key);

    TPM2B_MAX_BUFFER encrypted_inner_integrity = TPM2B_EMPTY_INIT;
    calculate_inner_integrity(&sensitive, &pubname, &enc_sensitive_key,
            &parent_pub.publicArea.parameters.rsaDetail.symmetric,
            &encrypted_inner_integrity);

    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    calculate_outer_integrity(
            parent_pub.publicArea.nameAlg,
            &pubname,
            &encrypted_inner_integrity,
            &hmac_key,
            &enc_key,
            &encrypted_duplicate_sensitive,
            &parent_pub.publicArea.parameters.rsaDetail.symmetric,
            &outer_hmac);


    create_import_key_private_data(&private,
            parent_pub.publicArea.nameAlg,
            &encrypted_duplicate_sensitive, &outer_hmac);

    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;
    res = encrypt_seed_with_tpm2_rsa_public_key(&protection_seed,
            &parent_pub,
            &encrypted_seed);
    if (!res) {
        LOG_ERR("Failed Seed Encryption\n");
        return false;
    }

    TPMT_SYM_DEF_OBJECT *sym_alg = &parent_pub.publicArea.parameters.rsaDetail.symmetric;

    return import_external_key_and_save_public_private_data(
            sapi_context,
            phandle,
            &encrypted_seed, &enc_sensitive_key,
            &private, &public,
            sym_alg);
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'G':
        ctx.key_type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_asymmetric
                |tpm2_alg_util_flags_symmetric);
        if (ctx.key_type == TPM2_ALG_ERROR) {
            LOG_ERR("Unsupported key type");
            return false;
        }
        return true;
    case 'k':
        ctx.input_key_file = value;
        break;
    case 'C':
        ctx.parent_ctx_arg = value;
        break;
    case 'K':
        ctx.parent_key_public_file = value;
        break;
    case 'u':
        ctx.import_key_public_file = value;
        break;
    case 'r':
        ctx.import_key_private_file = value;
        break;
    case 'A':
        if(!tpm2_util_string_to_uint32(value, &ctx.objectAttributes)) {
            LOG_ERR("Invalid object attribute, got\"%s\"", value);
            return false;
        }
        break;
    case 'g':
        ctx.name_alg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.name_alg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid name hashing algorithm, got\"%s\"", value);
            return false;
        }
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "import-key-alg",     required_argument, NULL, 'G'},
      { "input-key-file",     required_argument, NULL, 'k'},
      { "parent-key",         required_argument, NULL, 'C'},
      { "parent-key-public",  required_argument, NULL, 'K'},
      { "import-key-private", required_argument, NULL, 'r'},
      { "import-key-public",  required_argument, NULL, 'u'},
      { "object-attributes",  required_argument, NULL, 'A'},
      { "halg",               required_argument, NULL, 'g'},
    };

    *opts = tpm2_options_new("G:k:C:K:u:r:A:g:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

static bool load_rsa_key(const char *private_path,
        TPM2B_MAX_BUFFER *priv, TPM2B_MAX_BUFFER *pub) {

    bool res = false;
    RSA *k = NULL;
    const BIGNUM *p, *n;

    FILE *fk = fopen(private_path, "r");
    if (!fk) {
        LOG_ERR("Could not open file \"%s\", error: %s",
                private_path, strerror(errno));
        return false;
    }

    k = PEM_read_RSAPrivateKey(fk, NULL,
        NULL, NULL);
    fclose(fk);
    if (!k) {
         ERR_print_errors_fp (stderr);
         LOG_ERR("Reading PEM file \"%s\" failed", private_path);
         return false;
    }

#if OPENSSL_VERSION_NUMBER < 0x1010000fL /* OpenSSL 1.1.0 */
    p = k->p;
    n = k->n;
#else
    RSA_get0_factors(k, &p, NULL);
    RSA_get0_key(k, &n, NULL, NULL);
#endif

    unsigned priv_bytes = BN_num_bytes(p);
    if (priv_bytes > sizeof(priv->buffer)) {
        LOG_ERR("Expected prime \"p\" to be less than or equal to %zu,"
                " got: %u", sizeof(priv->buffer), priv_bytes);
        goto out;
    }

    priv->size = priv_bytes;

    int success = BN_bn2bin(p, priv->buffer);
    if (!success) {
        ERR_print_errors_fp (stderr);
        LOG_ERR("Could not convert prime \"p\"");
        goto out;
    }

    unsigned pub_bytes = BN_num_bytes(n);
    if (pub_bytes > sizeof(pub->buffer)) {
        LOG_ERR("Expected modulus \"n\" to be less than or equal to %zu,"
                " got: %u", sizeof(pub->buffer), pub_bytes);
        goto out;
    }

    pub->size = pub_bytes;

    success = BN_bn2bin(n, pub->buffer);
    if (!success) {
        ERR_print_errors_fp (stderr);
        LOG_ERR("Could not convert modulus \"n\"");
        goto out;
    }

    res = true;

out:
    RSA_free(k);

    return res;
}

static bool load_key(
        TPMI_ALG_PUBLIC key_type,
        const char *private_path,
        TPM2B_MAX_BUFFER *private, TPM2B_MAX_BUFFER *public) {

    switch(key_type) {
        case TPM2_ALG_AES:
            /* falls through */
        case TPM2_ALG_RSA:
            break;
        default:
            LOG_ERR("Invalid/ unsupported key algorithm for import, got\"0x%x\"",
                key_type);
            return false;
    }

    if (ctx.key_type == TPM2_ALG_RSA) {
        return load_rsa_key(private_path, private, public);
    }

    private->size = sizeof(private->buffer);
    bool res = files_load_bytes_from_path(ctx.input_key_file,
        private->buffer, &private->size);
    if (!res) {
        LOG_ERR("Input key file load failed");
        return false;
    }

    return true;
}

/**
 * Check all options and report as many errors as possible via LOG_ERR.
 * @return
 *  0 on success, -1 on failure.
 */
static int check_options(void) {

    int rc = 0;

    if (!ctx.input_key_file) {
        LOG_ERR("Expected to be imported key data to be specified via \"-k\","
                " missing option.");
        rc = -1;
    }

    if (!ctx.import_key_public_file) {
        LOG_ERR("Expected output public file missing, specify \"-u\","
                " missing option.");
        rc = -1;
    }

    if (!ctx.import_key_public_file) {
        LOG_ERR("Expected output private file missing, specify \"-r\","
                " missing option.");
        rc = -1;
    }

    if (!ctx.key_type) {
        LOG_ERR("Expected key type to be specified via \"-G\","
                " missing option.");
        rc = -1;
    }

    return rc;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();

    tpm2_loaded_object parent_ctx;

    result = tpm2_util_object_load(sapi_context, ctx.parent_ctx_arg,
                    &parent_ctx);
    if (!result) {
      goto out;
    }

    rc = check_options();
    if (rc) {
        goto out;
    }

    TPM2B_MAX_BUFFER private = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER public = TPM2B_EMPTY_INIT;;
    result = load_key(ctx.key_type, ctx.input_key_file, &private, &public);
    if (!result) {
        goto out;
    }

    result = key_import(sapi_context, parent_ctx.handle, &private, &public);
    if (!result) {
        goto out;
    }

    rc = 0;
out:
    return rc;
}
