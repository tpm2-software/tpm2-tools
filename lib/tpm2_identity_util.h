/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_IDENTITY_UTIL_H_
#define LIB_TPM2_IDENTITY_UTIL_H_

#include <tss2/tss2_sys.h>

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

/**
 * Generates HMAC integrity and symmetric encryption keys for TPM2 identies.
 *
 * @param parent_pub
 *  The public key used for seed generation and protection.
 * @param pubname
 *  The Name object associated with the parent_pub credential.
 * @param protection_seed
 *  The symmetric seed value used to generate protection keys.
 * @param protection_hmac_key
 *  The HMAC integrity key to populate.
 * @param protection_enc_key
 *  The symmetric encryption key to populate.
 * @return
 *  True on success, false on failure.
 */
bool tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        TPM2B_PUBLIC *parent_pub, TPM2B_NAME *pubname,
        TPM2B_DIGEST *protection_seed, TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key);

/**
 * Encrypts a randomly generated seed with parent public key for TPM2
 * credential protection process.
 *
 * @param protection_seed
 *  The identity structure protection seed to generate and populate.
 * @param parent_pub
 *  The public key used for encryption.
 * @param label
 *  Indicates label for the seed, such as "IDENTITY" or "DUPLICATE".
 * @param label_len
 *  Length of label.
 * @param encrypted_protection_seed
 *  The encrypted protection seed to populate.
 * @return
 *  True on success, false on failure.
 */
bool tpm2_identity_util_share_secret_with_public_key(
        TPM2B_DIGEST *protection_seed, TPM2B_PUBLIC *parent_pub,
        const unsigned char *label, int label_len,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed);

/**
 * Marshalls Credential Value and encrypts it with the symmetric encryption key.
 *
 * @param name_alg
 *  Hash algorithm used to compute Name of the public key.
 * @param sensitive
 *  The Credential Value to be marshalled and encrypted with symmetric key.
 * @param pubname
 *  The Name object corresponding to the public key.
 * @param enc_sensitive_key
 *  The symmetric encryption key.
 * @param sym_alg
 *  The algorithm used for the symmetric encryption key.
 * @param encrypted_inner_integrity
 *  The encrypted, marshalled Credential Value to populate.
 * @return
 *  True on success, false on failure.
 */
bool tpm2_identity_util_calculate_inner_integrity(TPMI_ALG_HASH name_alg,
        TPM2B_SENSITIVE *sensitive, TPM2B_NAME *pubname,
        TPM2B_DATA *enc_sensitive_key, TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_inner_integrity);

/**
 * Encrypts Credential Value with enc key and calculates HMAC with hmac key.
 *
 * @param parent_name_alg
 *  Hash algorithm used to compute Name of the public key.
 * @param pubname
 *  The Name object corresponding to the public key.
 * @param marshalled_sensitive
 *  Marshalled Credential Value to be encrypted with symmetric encryption key.
 * @param protection_hmac_key
 *  The HMAC integrity key.
 * @param protection_enc_key
 *  The symmetric encryption key.
 * @param sym_alg
 *  The algorithm used for the symmetric encryption key.
 * @param encrypted_duplicate_sensitive
 *  The encrypted Credential Value to populate.
 * @param outer_hmac
 *  The outer HMAC structure to populate.
 */
void tpm2_identity_util_calculate_outer_integrity(TPMI_ALG_HASH parent_name_alg,
        TPM2B_NAME *pubname, TPM2B_MAX_BUFFER *marshalled_sensitive,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key, TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac);

/**
 * Computes the name of a TPM key.
 *
 * @param public
 *  Public key structure
 * @param pubname
 *  The name structure to populate.
 */
bool tpm2_identity_create_name(TPM2B_PUBLIC *public, TPM2B_NAME *pubname);

#endif /* LIB_TPM2_IDENTITY_UTIL_H_ */
