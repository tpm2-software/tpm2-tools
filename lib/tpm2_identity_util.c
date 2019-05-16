//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// Copyright (c) 2019 Massachusetts Institute of Technology
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
//**********************************************************************

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm_kdfa.h"
#include "tpm2_openssl.h"

// Identity-related functionality that the TPM normally does, but using OpenSSL

#if defined(LIBRESSL_VERSION_NUMBER)
static int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
        const unsigned char *from, int flen, const unsigned char *param, int plen,
        const EVP_MD *md, const EVP_MD *mgf1md) {

    int ret = 0;
    int i, emlen = tlen - 1;
    unsigned char *db, *seed;
    unsigned char *dbmask, seedmask[EVP_MAX_MD_SIZE];
    int mdlen;

    if (md == NULL)
        md = EVP_sha1();
    if (mgf1md == NULL)
        mgf1md = md;

    mdlen = EVP_MD_size(md);

    if (flen > emlen - 2 * mdlen - 1) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    if (emlen < 2 * mdlen + 1) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP,
               RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    to[0] = 0;
    seed = to + 1;
    db = to + mdlen + 1;

    if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL))
        return 0;
    memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
    db[emlen - flen - mdlen - 1] = 0x01;
    memcpy(db + emlen - flen - mdlen, from, (unsigned int)flen);
    if (RAND_bytes(seed, mdlen) <= 0)
        return 0;

    dbmask = OPENSSL_malloc(emlen - mdlen);
    if (dbmask == NULL) {
        RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (PKCS1_MGF1(dbmask, emlen - mdlen, seed, mdlen, mgf1md) < 0)
        goto err;
    for (i = 0; i < emlen - mdlen; i++)
        db[i] ^= dbmask[i];

    if (PKCS1_MGF1(seedmask, mdlen, db, emlen - mdlen, mgf1md) < 0)
        goto err;
    for (i = 0; i < mdlen; i++)
        seed[i] ^= seedmask[i];

    ret = 1;

 err:
    OPENSSL_free(dbmask);

    return ret;
}
#endif

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

static bool encrypt_seed_with_tpm2_rsa_public_key(TPM2B_DIGEST *protection_seed,
        TPM2B_PUBLIC *parent_pub, unsigned char *label, int labelLen,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool rval = false;
    RSA *rsa = NULL;

    // Public modulus (RSA-only!)
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
    int return_code = RSA_padding_add_PKCS1_OAEP_mgf1(encoded,
            mod_size, protection_seed->buffer, protection_seed->size, label, labelLen,
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

bool tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        TPM2B_PUBLIC *parent_pub,
        TPM2B_NAME *pubname,
        TPM2B_DIGEST *protection_seed,
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


bool tpm2_identity_util_encrypt_seed_with_public_key(TPM2B_DIGEST *protection_seed,
        TPM2B_PUBLIC *parent_pub, unsigned char *label, int labelLen,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool result = false;
    TPMI_ALG_PUBLIC alg = parent_pub->publicArea.type;
    
    switch (alg) {
    case TPM2_ALG_RSA:
        result = encrypt_seed_with_tpm2_rsa_public_key(protection_seed, 
                parent_pub, label, labelLen, encrypted_protection_seed);
        break;
    case TPM2_ALG_ECC:
        LOG_ERR("Algorithm '%s' not supported yet", tpm2_alg_util_algtostr(alg));
        result = false;
        break;
    default:
        LOG_ERR("Cannot handle algorithm, got: %s", tpm2_alg_util_algtostr(alg));
        return false;
    }
    
    return result;
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

static bool aes_encrypt_buffers(TPMT_SYM_DEF_OBJECT *sym, uint8_t *encryption_key,
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

        rc = EVP_EncryptUpdate(ctx, &cipher_text->buffer[offset], &output_len, b, l);
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

bool tpm2_identity_util_calculate_inner_integrity(
        TPMI_ALG_HASH name_alg, 
        TPM2B_SENSITIVE *sensitive, 
        TPM2B_NAME *pubname, 
        TPM2B_DATA *enc_sensitive_key,
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
    UINT16 hash_size = tpm2_alg_util_get_hash_size(name_alg);
    Tss2_MU_UINT16_Marshal(hash_size, marshalled_sensitive_and_name_digest,
            sizeof(uint16_t), &digest_size_info);

    digester d = tpm2_openssl_halg_to_digester(name_alg);
    d(buffer_marshalled_sensitiveArea,
            marshalled_sensitive_size_info + marshalled_sensitive_size
                    + pubname->size,
            marshalled_sensitive_and_name_digest + digest_size_info);

    //Inner integrity
    encrypted_inner_integrity->size = marshalled_sensitive_size_info
            + marshalled_sensitive_size + pubname->size;

    return aes_encrypt_buffers(
            sym_alg,
            enc_sensitive_key->buffer,
            marshalled_sensitive_and_name_digest, 
            hash_size + digest_size_info,
            buffer_marshalled_sensitiveArea, 
            marshalled_sensitive_size_info + marshalled_sensitive_size,
            encrypted_inner_integrity);
}

void tpm2_identity_util_calculate_outer_integrity(
        TPMI_ALG_HASH parent_name_alg,
        TPM2B_NAME *pubname,
        TPM2B_MAX_BUFFER *marshalled_sensitive,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac) {

    //Calculate dupSensitive
    encrypted_duplicate_sensitive->size =
            marshalled_sensitive->size;

    aes_encrypt_buffers(
            sym_alg,
            protection_enc_key->buffer,
            marshalled_sensitive->buffer,
            marshalled_sensitive->size,
            NULL, 0,
            encrypted_duplicate_sensitive);
    //Calculate outerHMAC
    hmac_outer_integrity(
            parent_name_alg,
            encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size,
            pubname->name,
            pubname->size, 
            protection_hmac_key->buffer,
            outer_hmac);
}
