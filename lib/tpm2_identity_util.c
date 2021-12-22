/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include <openssl/rand.h>

#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_identity_util.h"
#include "tpm2_kdfa.h"
#include "tpm2_kdfe.h"
#include "tpm2_openssl.h"

// Identity-related functionality that the TPM normally does, but using OpenSSL

static TPM2_KEY_BITS get_pub_asym_key_bits(TPM2B_PUBLIC *public) {

    TPMU_PUBLIC_PARMS *p = &public->publicArea.parameters;
    switch (public->publicArea.type) {
    case TPM2_ALG_ECC:
        /* fall-thru */
    case TPM2_ALG_RSA:
        return p->asymDetail.symmetric.keyBits.sym;
        /* no default */
    }

    return 0;
}

static bool share_secret_with_tpm2_rsa_public_key(TPM2B_DIGEST *protection_seed,
        TPM2B_PUBLIC *parent_pub, const unsigned char *label, int label_len,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool rval = false;
    EVP_PKEY_CTX *ctx = NULL;

    EVP_PKEY *pkey = convert_pubkey_RSA(&parent_pub->publicArea);
    if (pkey == NULL) {
        LOG_ERR("Failed to retrieve public key");
        return false;
    }

    TPMI_ALG_HASH parent_name_alg = parent_pub->publicArea.nameAlg;

    /*
     * RSA Secret Sharing uses a randomly generated seed (Part 1, B.10.3).
     */
    protection_seed->size = tpm2_alg_util_get_hash_size(parent_name_alg);
    int rc = RAND_bytes(protection_seed->buffer, protection_seed->size);
    if (rc != 1) {
        LOG_ERR("Failed to get random bytes");
        goto error;
    }

    /*
     * The seed value will be OAEP encrypted with a given L parameter.
     */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        LOG_ERR("Failed EVP_PKEY_CTX_new");
        goto error;
    }

    rc = EVP_PKEY_encrypt_init(ctx);
    if (rc <= 0) {
        LOG_ERR("Failed EVP_PKEY_encrypt_init");
        goto error;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (rc <= 0) {
        LOG_ERR("Failed EVP_PKEY_CTX_set_rsa_padding");
        goto error;
    }

    rc = EVP_PKEY_CTX_set_rsa_oaep_md(ctx,
            tpm2_openssl_md_from_tpmhalg(parent_name_alg));
    if (rc <= 0) {
        LOG_ERR("Failed EVP_PKEY_CTX_set_rsa_oaep_md");
        goto error;
    }

    // the library will take ownership of the label
    char *newlabel = strdup((const char *)label);
    if (newlabel == NULL) {
        LOG_ERR("Failed to allocate label");
        goto error;
    }

    rc = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, newlabel, label_len);
    if (rc <= 0) {
        LOG_ERR("Failed EVP_PKEY_CTX_set0_rsa_oaep_label");
        free(newlabel);
        goto error;
    }

    size_t outlen = sizeof(TPMU_ENCRYPTED_SECRET);
    if (EVP_PKEY_encrypt(ctx, encrypted_protection_seed->secret, &outlen,
            protection_seed->buffer, protection_seed->size) <= 0) {
        LOG_ERR("Failed EVP_PKEY_encrypt\n");
        goto error;
    }
    encrypted_protection_seed->size = outlen;
    rval = true;

error:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rval;
}

bool tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        TPM2B_PUBLIC *parent_pub, TPM2B_NAME *pubname,
        TPM2B_DIGEST *protection_seed, TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key) {

    TPM2B null_2b = { .size = 0 };

    TPMI_ALG_HASH parent_alg = parent_pub->publicArea.nameAlg;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_alg);

    TSS2_RC rval = tpm2_kdfa(parent_alg, (TPM2B *) protection_seed, "INTEGRITY",
            &null_2b, &null_2b, parent_hash_size * 8, protection_hmac_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_KEY_BITS pub_key_bits = get_pub_asym_key_bits(parent_pub);

    rval = tpm2_kdfa(parent_alg, (TPM2B *) protection_seed, "STORAGE",
            (TPM2B *) pubname, &null_2b, pub_key_bits, protection_enc_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    return true;
}

bool tpm2_identity_util_share_secret_with_public_key(
        TPM2B_DIGEST *protection_seed, TPM2B_PUBLIC *parent_pub,
        const unsigned char *label, int label_len,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool result = false;
    TPMI_ALG_PUBLIC alg = parent_pub->publicArea.type;

    switch (alg) {
    case TPM2_ALG_RSA:
        result = share_secret_with_tpm2_rsa_public_key(protection_seed,
                parent_pub, label, label_len, encrypted_protection_seed);
        break;
    case TPM2_ALG_ECC:
        result = ecdh_derive_seed_and_encrypted_seed(parent_pub,
                label, label_len,
                protection_seed, encrypted_protection_seed);
        break;
    default:
        LOG_ERR("Cannot handle algorithm, got: %s",
                tpm2_alg_util_algtostr(alg, tpm2_alg_util_flags_any));
        return false;
    }

    return result;
}

static const EVP_CIPHER *tpm_alg_to_ossl(TPMT_SYM_DEF_OBJECT *sym) {

    switch (sym->algorithm) {
    case TPM2_ALG_AES: {
        switch (sym->keyBits.aes) {
        case 128:
            return EVP_aes_128_cfb();
        case 256:
            return EVP_aes_256_cfb();
            /* no default */
        }
        break;
    }
#if HAVE_EVP_SM4_CFB
    case TPM2_ALG_SM4: {
        switch (sym->keyBits.sm4) {
        case 128:
            return EVP_sm4_cfb();
            /* no default */
        }
        break;
    }
#endif
        /* no default */
    }

    LOG_ERR("Unsupported parent key symmetric parameters");

    return NULL;
}

static bool aes_encrypt_buffers(TPMT_SYM_DEF_OBJECT *sym,
        uint8_t *encryption_key, uint8_t *buf1, size_t buf1_len, uint8_t *buf2,
        size_t buf2_len, TPM2B_MAX_BUFFER *cipher_text) {

    bool result = false;

    unsigned offset = 0;
    size_t total_len = buf1_len + buf2_len;

    if (total_len > sizeof(cipher_text->buffer)) {
        LOG_ERR("Plaintext too big, got %zu, expected less then %zu", total_len,
                sizeof(cipher_text->buffer));
        return false;
    }

    const EVP_CIPHER *cipher = tpm_alg_to_ossl(sym);
    if (!cipher) {
        return false;
    }

    const unsigned char iv[512] = { 0 };

    if (((unsigned long) EVP_CIPHER_iv_length(cipher)) > sizeof(iv)) {
        LOG_ERR("IV size is bigger then IV buffer size");
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int rc = EVP_EncryptInit_ex(ctx, cipher, NULL, encryption_key, iv);
    if (!rc) {
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t *bufs[2] = { buf1, buf2 };

    size_t lens[ARRAY_LEN(bufs)] = { buf1_len, buf2_len };

    unsigned i;
    for (i = 0; i < ARRAY_LEN(bufs); i++) {

        uint8_t *b = bufs[i];
        size_t l = lens[i];

        if (!b) {
            continue;
        }

        int output_len = total_len - offset;

        rc = EVP_EncryptUpdate(ctx, &cipher_text->buffer[offset], &output_len,
                b, l);
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
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

static void hmac_outer_integrity(TPMI_ALG_HASH parent_name_alg,
        uint8_t *buffer1, uint16_t buffer1_size, uint8_t *buffer2,
        uint16_t buffer2_size, uint8_t *hmac_key,
        TPM2B_DIGEST *outer_integrity_hmac) {

    uint8_t to_hmac_buffer[TPM2_MAX_DIGEST_BUFFER];
    memcpy(to_hmac_buffer, buffer1, buffer1_size);
    memcpy(to_hmac_buffer + buffer1_size, buffer2, buffer2_size);
    uint32_t size = 0;

    UINT16 hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);

    HMAC(tpm2_openssl_md_from_tpmhalg(parent_name_alg), hmac_key, hash_size,
            to_hmac_buffer, buffer1_size + buffer2_size,
            outer_integrity_hmac->buffer, &size);
    outer_integrity_hmac->size = size;
}

bool tpm2_identity_util_calculate_inner_integrity(TPMI_ALG_HASH name_alg,
        TPM2B_SENSITIVE *sensitive, TPM2B_NAME *pubname,
        TPM2B_DATA *enc_sensitive_key, TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_inner_integrity) {

    TSS2_RC rval;

    //Marshal sensitive area
    uint8_t buffer_marshalled_sensitiveArea[TPM2_MAX_DIGEST_BUFFER] = { 0 };
    size_t marshalled_sensitive_size = 0;
    rval = Tss2_MU_TPMT_SENSITIVE_Marshal(&sensitive->sensitiveArea,
            buffer_marshalled_sensitiveArea + sizeof(uint16_t),
            TPM2_MAX_DIGEST_BUFFER, &marshalled_sensitive_size);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERR("Error serializing the sensitive data");
        return false;
    }

    size_t marshalled_sensitive_size_info = 0;
    rval = Tss2_MU_UINT16_Marshal(marshalled_sensitive_size,
            buffer_marshalled_sensitiveArea, sizeof(uint16_t),
            &marshalled_sensitive_size_info);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERR("Error serializing the sensitive size");
        return false;
    }

    //concatenate NAME
    memcpy(buffer_marshalled_sensitiveArea + marshalled_sensitive_size +
        marshalled_sensitive_size_info, pubname->name, pubname->size);

    //Digest marshalled-sensitive || name
    uint8_t *marshalled_sensitive_and_name_digest =
            buffer_marshalled_sensitiveArea + marshalled_sensitive_size
                    + marshalled_sensitive_size_info + pubname->size;
    size_t digest_size_info = 0;
    UINT16 hash_size = tpm2_alg_util_get_hash_size(name_alg);
    rval = Tss2_MU_UINT16_Marshal(hash_size, marshalled_sensitive_and_name_digest,
            sizeof(uint16_t), &digest_size_info);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERR("Error serializing the name size");
        return false;
    }

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(name_alg);
    if (!md) {
        LOG_ERR("Algorithm not supported: %x", name_alg);
        return false;
    }
    int rc = EVP_Digest(buffer_marshalled_sensitiveArea,
                        marshalled_sensitive_size_info + marshalled_sensitive_size
                            + pubname->size,
                        marshalled_sensitive_and_name_digest + digest_size_info,
                        NULL, md, NULL);
    if (!rc) {
        LOG_ERR("Hash calculation failed");
        return false;
    }

    //Inner integrity
    encrypted_inner_integrity->size = marshalled_sensitive_size_info
            + marshalled_sensitive_size + pubname->size;

    return aes_encrypt_buffers(sym_alg, enc_sensitive_key->buffer,
            marshalled_sensitive_and_name_digest, hash_size + digest_size_info,
            buffer_marshalled_sensitiveArea,
            marshalled_sensitive_size_info + marshalled_sensitive_size,
            encrypted_inner_integrity);
}

void tpm2_identity_util_calculate_outer_integrity(TPMI_ALG_HASH parent_name_alg,
        TPM2B_NAME *pubname, TPM2B_MAX_BUFFER *marshalled_sensitive,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key, TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac) {

    //Calculate dupSensitive
    encrypted_duplicate_sensitive->size = marshalled_sensitive->size;

    aes_encrypt_buffers(sym_alg, protection_enc_key->buffer,
            marshalled_sensitive->buffer, marshalled_sensitive->size,
            NULL, 0, encrypted_duplicate_sensitive);
    //Calculate outerHMAC
    hmac_outer_integrity(parent_name_alg, encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size, pubname->name, pubname->size,
            protection_hmac_key->buffer, outer_hmac);
}

bool tpm2_identity_create_name(TPM2B_PUBLIC *public, TPM2B_NAME *pubname) {

    /*
     * A TPM2B_NAME is the name of the algorithm, followed by the hash.
     * Calculate the name by:
     * 1. Marshaling the name algorithm
     * 2. Marshaling the TPMT_PUBLIC past the name algorithm from step 1.
     * 3. Hash the TPMT_PUBLIC portion in marshaled data.
     */
    TSS2_RC rval;

    TPMI_ALG_HASH name_alg = public->publicArea.nameAlg;

    // Step 1 - set beginning of name to hash alg
    size_t hash_offset = 0;
    rval = Tss2_MU_UINT16_Marshal(name_alg, pubname->name, pubname->size,
            &hash_offset);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERR("Error serializing the name size");
        return false;
    }

    // Step 2 - marshal TPMTP
    TPMT_PUBLIC marshaled_tpmt;
    size_t tpmt_marshalled_size = 0;
    rval = Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea,
            (uint8_t *) &marshaled_tpmt, sizeof(public->publicArea),
            &tpmt_marshalled_size);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERR("Error serializing the public area");
        return false;
    }

    // Step 3 - Hash the data into name just past the alg type.
    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(name_alg);
    if (!md) {
        LOG_ERR("Algorithm not supported: %x", name_alg);
        return false;
    }

    unsigned int hash_size;
    int rc = EVP_Digest(&marshaled_tpmt, tpmt_marshalled_size,
                        pubname->name + hash_offset, &hash_size, md, NULL);
    if (!rc) {
        LOG_ERR("Hash calculation failed");
        return false;
    }

    //Set the name size, UINT16 followed by HASH
    pubname->size = hash_size + hash_offset;

    return true;
}
