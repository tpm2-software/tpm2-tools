/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ecdh.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "tpm2_openssl.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

TSS2_RC tpm2_kdfe(
        TPMI_ALG_HASH hash_alg, TPM2B_ECC_PARAMETER *Z,
        unsigned char *label, int label_length,
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

    digester d = tpm2_openssl_halg_to_digester(hash_alg);

    for (done = 0, counter = 1; done < bytes; done += hash_size, counter++) {
        counter_be = tpm2_util_hton_32(counter);
        memcpy(hash_input.buffer, &counter_be, 4);

        d(hash_input.buffer, hash_input.size, result_key->buffer + done);
    }
    // truncate the result to the desired size
    result_key->size = bytes;

    return rval;
}

static EC_POINT * tpm2_get_EC_public_key(TPM2B_PUBLIC *public) {
    EC_POINT *q = NULL;
    BIGNUM *bn_qx, *bn_qy;
    EC_KEY *key;
    const EC_GROUP *group;
    bool rval;
    TPMS_ECC_PARMS *tpm_ecc   = &public->publicArea.parameters.eccDetail;
    TPMS_ECC_POINT *tpm_point = &public->publicArea.unique.ecc;

    int nid = tpm2_ossl_curve_to_nid(tpm_ecc->curveID);
    if (nid < 0) {
        return NULL;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key) {
        LOG_ERR("Failed to create EC key from nid");
        return NULL;
    }

    bn_qx = BN_bin2bn(tpm_point->x.buffer, tpm_point->x.size, NULL);
    bn_qy = BN_bin2bn(tpm_point->y.buffer, tpm_point->y.size, NULL);
    if ((bn_qx == NULL) || (bn_qy == NULL)) {
        LOG_ERR("Could not convert EC public key to BN");
        goto out;
    }
    group = EC_KEY_get0_group(key);
    if (!group) {
        LOG_ERR("EC key missing group");
        goto out;
    }
    q = EC_POINT_new(group);
    if (q == NULL) {
        LOG_ERR("Could not allocate EC_POINT");
        goto out;
    }

    rval = EC_POINT_set_affine_coordinates_tss(group, q, bn_qx, bn_qy, NULL);
    if (rval == false) {
        LOG_ERR("Could not set affine_coordinates");
        EC_POINT_free(q);
        q = NULL;
    }

out:
    if (bn_qx) {
        BN_free(bn_qx);
    }
    if (bn_qy) {
        BN_free(bn_qy);
    }
    if (key) {
        EC_KEY_free(key);
    }

    return q;
}


static bool get_public_key_from_ec_key(EC_KEY *key, TPMS_ECC_POINT *point) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    const EC_POINT *pubkey = EC_KEY_get0_public_key(key);
    unsigned int nbx, nby;
    bool result = false;

    if ((x == NULL) || (y == NULL) || (pubkey == NULL)) {
        LOG_ERR("Failed to allocate memory to store EC public key.");
        goto out;
    }

    EC_POINT_get_affine_coordinates_tss(EC_KEY_get0_group(key),
            pubkey, x, y, NULL);
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
    if (x) {
        BN_free(x);
    }
    if (y) {
        BN_free(y);
    }
    return result;
}


static int get_ECDH_shared_secret(EC_KEY *key,
        const EC_POINT *p_pub, TPM2B_ECC_PARAMETER *secret) {

    int shared_secret_length;

    shared_secret_length = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    shared_secret_length = (shared_secret_length + 7) / 8;
    if ((size_t) shared_secret_length > sizeof(secret->buffer)) {
        return -1;
    }
    secret->size = ECDH_compute_key(secret->buffer,
            shared_secret_length, p_pub, key, NULL);
    return secret->size;
}



bool ecdh_derive_seed_and_encrypted_seed(
        TPM2B_PUBLIC *parent_pub,
        unsigned char *label, int label_len,
        TPM2B_DIGEST *seed,
        TPM2B_ENCRYPTED_SECRET *out_sym_seed) {

    TPMS_ECC_PARMS *tpm_ecc = &parent_pub->publicArea.parameters.eccDetail;
    TPMI_ALG_HASH parent_name_alg = parent_pub->publicArea.nameAlg;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);
    bool result = false;
    EC_KEY *key = NULL;
    EC_POINT *qsv = NULL;
    TPMS_ECC_POINT qeu;
    bool qeu_is_valid;
    TPM2B_ECC_PARAMETER ecc_secret;

    // generate an ephemeral key
    int nid = tpm2_ossl_curve_to_nid(tpm_ecc->curveID);
    if (nid >= 0) {
        key = EC_KEY_new_by_curve_name(nid);
    }
    if (key == NULL) {
        LOG_ERR("Failed to create EC key from curveID");
        return false;
    }
    EC_KEY_generate_key(key);

    // get public key for the ephemeral key
    qeu_is_valid = get_public_key_from_ec_key(key, &qeu);
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
    qsv = tpm2_get_EC_public_key(parent_pub);
    if (qsv == NULL) {
        LOG_ERR("Could not get parent's public key");
        goto out;
    }

    get_ECDH_shared_secret(key, qsv, &ecc_secret);

    /* derive seed using KDFe */
    TPM2B_ECC_PARAMETER *party_u_info = &qeu.x;
    TPM2B_ECC_PARAMETER *party_v_info = &parent_pub->publicArea.unique.ecc.x;
    tpm2_kdfe(parent_name_alg, &ecc_secret, label, label_len,
            party_u_info, party_v_info, parent_hash_size * 8,
            (TPM2B_MAX_BUFFER *) seed);

    result = true;

out:
    if (qsv) {
        EC_POINT_free(qsv);
    }
    if (key) {
        EC_KEY_free(key);
    }
    return result;
}
