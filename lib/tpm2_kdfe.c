/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/ecdh.h>
#else
#include <openssl/core_names.h>
#endif
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

TSS2_RC tpm2_kdfe(
        TPMI_ALG_HASH hash_alg, TPM2B_ECC_PARAMETER *Z,
        const unsigned char *label, int label_length,
        TPM2B_ECC_PARAMETER *party_u, TPM2B_ECC_PARAMETER *party_v,
        UINT16 size_in_bits, TPM2B_MAX_BUFFER  *result_key ) {

    TPM2B_MAX_BUFFER hash_input;
    TPM2B_DATA use;
    int bytes = ((size_in_bits + 7) / 8);
    int done;
    UINT32 counter, counter_be;
    UINT16 hash_size = tpm2_alg_util_get_hash_size(hash_alg);
    TSS2_RC rval = TPM2_RC_SUCCESS;

    memcpy(use.buffer, label, label_length);
    use.size = label_length;

    /*
     * Hash[i] := H(hash_input), where otherInfo := Use | PartyUInfo|PartyVInfo
     * hash_input := counter | Z | OtherInfo
     */
    hash_input.size = 4; // room for the counter
    tpm2_util_concat_buffer(&hash_input, (TPM2B *) Z);
    tpm2_util_concat_buffer(&hash_input, (TPM2B *) &use);
    tpm2_util_concat_buffer(&hash_input, (TPM2B *) party_u);
    tpm2_util_concat_buffer(&hash_input, (TPM2B *) party_v);

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(hash_alg);
    if (!md) {
        LOG_ERR("Algorithm not supported: %x", hash_alg);
        return TPM2_RC_HASH;
    }

    for (done = 0, counter = 1; done < bytes; done += hash_size, counter++) {
        counter_be = tpm2_util_hton_32(counter);
        memcpy(hash_input.buffer, &counter_be, 4);

        int rc = EVP_Digest(hash_input.buffer, hash_input.size,
                            result_key->buffer + done, NULL, md, NULL);
        if (!rc) {
            LOG_ERR("Hash calculation failed");
            return TPM2_RC_MEMORY;
        }
    }
    // truncate the result to the desired size
    result_key->size = bytes;

    return rval;
}

static bool get_public_key_from_ec_key(EVP_PKEY *pkey, TPMS_ECC_POINT *point) {
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    unsigned int nbx, nby;
    bool result = false;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EC_KEY *key = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_POINT *pubkey = EC_KEY_get0_public_key(key);

    x = BN_new();
    y = BN_new();
    if ((x == NULL) || (y == NULL) || (pubkey == NULL)) {
        LOG_ERR("Failed to allocate memory to store EC public key.");
        goto out;
    }

    EC_POINT_get_affine_coordinates_tss(EC_KEY_get0_group(key),
            pubkey, x, y, NULL);
#else
    int rc = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x);
    if (!rc) {
        LOG_ERR("Failed to get EC public key X.");
        goto out;
    }
    rc = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
    if (!rc) {
        LOG_ERR("Failed to get EC public key Y.");
        goto out;
    }
#endif
    nbx = BN_num_bytes(x);
    nby = BN_num_bytes(y);
    if ((nbx > sizeof(point->x.buffer))||
            (nby > sizeof(point->y.buffer))) {
        LOG_ERR("EC public key has too many bits.");
        goto out;
    }

    point->x.size = nbx;
    point->y.size = nby;
    BN_bn2bin(x, point->x.buffer);
    BN_bn2bin(y, point->y.buffer);
    result = true;

out:
    BN_free(x);
    BN_free(y);
    return result;
}


static int get_ECDH_shared_secret(EVP_PKEY *pkey,
        EVP_PKEY *p_pub, TPM2B_ECC_PARAMETER *secret) {

    EVP_PKEY_CTX *ctx;
    int result = -1;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return -1;

    int rc = EVP_PKEY_derive_init(ctx);
    if (rc <= 0)
        goto out;

    rc = EVP_PKEY_derive_set_peer(ctx, p_pub);
    if (rc <= 0)
        goto out;

    size_t shared_secret_length = sizeof(secret->buffer);
    rc = EVP_PKEY_derive(ctx, secret->buffer, &shared_secret_length);
    if (rc <= 0)
        goto out;

    secret->size = shared_secret_length;
    result = secret->size;

out:
    EVP_PKEY_CTX_free(ctx);
    return result;
}



bool ecdh_derive_seed_and_encrypted_seed(
        TPM2B_PUBLIC *parent_pub,
        const unsigned char *label, int label_len,
        TPM2B_DIGEST *seed,
        TPM2B_ENCRYPTED_SECRET *out_sym_seed) {

    TPMS_ECC_PARMS *tpm_ecc = &parent_pub->publicArea.parameters.eccDetail;
    TPMI_ALG_HASH parent_name_alg = parent_pub->publicArea.nameAlg;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);
    bool result = false;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *qsv = NULL;
    TPMS_ECC_POINT qeu;
    bool qeu_is_valid;
    TPM2B_ECC_PARAMETER ecc_secret;

    // generate an ephemeral key
    int nid = tpm2_ossl_curve_to_nid(tpm_ecc->curveID);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        LOG_ERR("Failed to create key creation context");
        return false;
    }

    int rc = EVP_PKEY_keygen_init(ctx);
    if (rc <= 0) {
        LOG_ERR("Failed to initialize key creation");
        goto out;
    }

    rc = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    if (rc <= 0) {
        LOG_ERR("Failed to set EC curve NID %i", nid);
        goto out;
    }

    rc = EVP_PKEY_keygen(ctx, &pkey);
    if (rc <= 0) {
        LOG_ERR("Failed to generate the ephemeral EC key");
        goto out;
    }

    // get public key for the ephemeral key
    qeu_is_valid = get_public_key_from_ec_key(pkey, &qeu);
    if (qeu_is_valid == false) {
        LOG_ERR("Could not get the ECC public key");
        goto out;
    }

    /* marshal the public key to encrypted seed */
    size_t offset = 0;
    TSS2_RC rval;
    rval = Tss2_MU_TPMS_ECC_POINT_Marshal(&qeu,
            out_sym_seed->secret, sizeof(out_sym_seed->secret), &offset);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Error serializing the ECC public key");
        goto out;
    }
    out_sym_seed->size = offset;

    /* get parents public key */
    qsv = convert_pubkey_ECC(&parent_pub->publicArea);
    if (qsv == NULL) {
        LOG_ERR("Could not get parent's public key");
        goto out;
    }

    rc = get_ECDH_shared_secret(pkey, qsv, &ecc_secret);
    if (rc <= 0) {
        LOG_ERR("Could not derive shared secret");
        goto out;
    }

    /* derive seed using KDFe */
    TPM2B_ECC_PARAMETER *party_u_info = &qeu.x;
    TPM2B_ECC_PARAMETER *party_v_info = &parent_pub->publicArea.unique.ecc.x;
    tpm2_kdfe(parent_name_alg, &ecc_secret, label, label_len,
            party_u_info, party_v_info, parent_hash_size * 8,
            (TPM2B_MAX_BUFFER *) seed);

    result = true;

out:
    EVP_PKEY_free(qsv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return result;
}
