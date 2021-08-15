/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_OPENSSL_H_
#define LIB_TPM2_OPENSSL_H_

#include <tss2/tss2_sys.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

#include "pcr.h"

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates(group, tpm_pub_key, bn_x, bn_y, dmy)

#else
#define EC_POINT_set_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_set_affine_coordinates_GFp(group, tpm_pub_key, bn_x, bn_y, dmy)

#define EC_POINT_get_affine_coordinates_tss(group, tpm_pub_key, bn_x, bn_y, dmy) \
        EC_POINT_get_affine_coordinates_GFp(group, tpm_pub_key, bn_x, bn_y, dmy)
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */

static inline const char *tpm2_openssl_get_err(void) {
    return ERR_error_string(ERR_get_error(), NULL);
}

/**
 * Get an openssl hash algorithm ID from a tpm hashing algorithm ID.
 * @param algorithm
 *  The tpm algorithm to get the corresponding openssl version of.
 * @return
 *  The openssl hash algorithm id.
 */
int tpm2_openssl_halgid_from_tpmhalg(TPMI_ALG_HASH algorithm);

/**
 * Get an openssl message digest from a tpm hashing algorithm.
 * @param algorithm
 *  The tpm algorithm to get the corresponding openssl version of.
 * @return
 *  A pointer to a message digester or NULL on failure.
 */
const EVP_MD *tpm2_openssl_md_from_tpmhalg(TPMI_ALG_HASH algorithm);

/**
 * Hash a byte buffer.
 * @param halg
 *  The hashing algorithm to use.
 * @param buffer
 *  The byte buffer to be hashed.
 * @param length
 *  The length of the byte buffer to hash.
 ^ * @param digest
 ^ *  The result of hashing digests with halg.
 * @return
 *  true on success, false on error.
 */
bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer,
        UINT16 length, TPM2B_DIGEST *digest);

/**
 * Hash a list of PCR digests.
 * @param halg
 *  The hashing algorithm to use.
 * @param digests
 *  The list of PCR digests to hash.
 ^ * @param digest
 ^ *  The result of hashing digests with halg.
 * @return
 *  true on success, false on error.
 */
bool tpm2_openssl_hash_pcr_values(TPMI_ALG_HASH halg, TPML_DIGEST *digests,
        TPM2B_DIGEST *digest);

/**
 * Hash a list of PCR digests, supporting multiple banks.
 * @param halg
 *  The hashing algorithm to use.
 * @param pcr_select
 *  The list that specifies which PCRs are selected.
 * @param pcrs
 *  The list of PCR banks, each containing a list of PCR digests to hash.
 ^ * @param digest
 ^ *  The result of hashing digests with halg.
 * @return
 *  true on success, false on error.
 */
bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hashAlg,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest);

/*
 * Hash a list of PCR digests, supporting multiple banks.
 * The data in TPML_PCR_SELECTION and tpm2_pcrs is in little endian format.
 *
 * @param halg
 *  The hashing algorithm to use.
 * @param pcr_select
 *  The list that specifies which PCRs are selected.
 * @param pcrs
 *  The list of PCR banks, each containing a list of PCR digests to hash.
 ^ * @param digest
 ^ *  The result of hashing digests with halg.
 * @return
 *  true on success, false on error.
 */
bool tpm2_openssl_hash_pcr_banks_le(TPMI_ALG_HASH hashAlg,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest);

/**
 * Extend a PCR with a new digest.
 * @param halg
 *  The hashing algorithm to use.
 * @param pcr
 *  A buffer with the current value of the PCR, will be updated in place.
 * @param data
 *  The new digest to be added to the current PCR.
 * @param length
 *  Length of the new data to be added to the digest.
 * @return
 *  true on success, false on error.
 */
bool tpm2_openssl_pcr_extend(TPMI_ALG_HASH halg, BYTE *pcr,
        const BYTE *data, UINT16 length);

typedef enum tpm2_openssl_load_rc tpm2_openssl_load_rc;
enum tpm2_openssl_load_rc {
    lprc_error = 0, /* an error has occurred */
    lprc_private = 1 << 0, /* successfully loaded a private portion of object */
    lprc_public = 1 << 1, /* successfully loaded a public portion of object */
};

/**
 * Helper routine for gathering if the loading status included a public
 * portion of an object.
 *
 * @param load_status
 *  The loading status obtained from a call to tpm2_openssl_load_private().
 * @return
 *  True if the load status indicates it loaded a public portion of an object,
 *  false otherwise.
 */
static inline bool tpm2_openssl_did_load_public(
        tpm2_openssl_load_rc load_status) {
    return (load_status & lprc_public);
}

/**
 * Loads a private portion of a key, and possibly the public portion.
 * For asymmetric algorithms the public data is in  private PEM file.
 * For symmetric keys, the file type is raw. For asymmetric keys, the
 * file type is a PEM file.
 *
 * This ONLY supports AES, ECC and RSA.
 *
 * It populates the sensitive seed with a random value for symmetric keys.
 *
 * @param path
 *  The path to load from.
 * @param path
 *  The passphrase for the input file.
 * @param alg
 *  algorithm type to import.
 * @param pub
 *  The public structure to populate. Note that nameAlg must be populated.
 * @param priv
 *  The sensitive structure to populate.
 *
 * @returns
 *  A private object loading status
 */
tpm2_openssl_load_rc tpm2_openssl_load_private(const char *path,
        const char *pass, TPMI_ALG_PUBLIC alg, TPM2B_PUBLIC *pub,
        TPM2B_SENSITIVE *priv);


/**
 * Load an OpenSSL private key and configure all of the flags based on
 * a parent key, policy, attributes, and authorization.
 */
bool tpm2_openssl_import_keys(
    TPM2B_PUBLIC *parent_pub,
    TPM2B_SENSITIVE *private,
    TPM2B_PUBLIC *public,
    TPM2B_ENCRYPTED_SECRET *encrypted_seed,
    const char *input_key_file,
    TPMI_ALG_PUBLIC key_type,
    const char *auth_key_file,
    const char *policy_file,
    const char *key_auth_str,
    char *attrs_str,
    const char *name_alg_str
);

/**
 * Loads a public portion of a key from a file. Files can be the raw key, in the case
 * of symmetric ciphers, or a PEM file.
 *
 * @param path
 *  The path to load from.
 * @param alg
 *  algorithm type to import.
 * @param pub
 *  The public structure to populate.
 * @return
 *  True on success, false on failure.
 */
bool tpm2_openssl_load_public(const char *path, TPMI_ALG_PUBLIC alg,
        TPM2B_PUBLIC *pub);

/**
 * Maps an ECC curve to an openssl nid value.
 * @param curve
 *  The curve to map.
 * @return
 *  -1 on error or a >=0 nid on success.
 */
int tpm2_ossl_curve_to_nid(TPMI_ECC_CURVE curve);

#endif /* LIB_TPM2_OPENSSL_H_ */
