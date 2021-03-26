/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_TPM_KDFE_H_
#define SRC_TPM_KDFE_H_

#include <tss2/tss2_sys.h>

/**
 * The KDFe function, defined in Appendix C.6.1 of TPM 2.0 Library
 * Specification Part1
 *  (https://trustedcomputinggroup.org/resource/tpm-library-specification/)
 *
 * @param hash_alg
 *  The hashing algorithm to use.
 * @param Z
 *  The ECDH shared secret. Z is the x coordinate of the product of d and Q,
 *  where d is a private key and Q is the other party's public key.
 * @param label
 *  The label value. ie. "DUPLICATE\0" or "IDENTITY\0".
 * @param label_length
 *  Length of the label.
 * @param party_u_info
 *  The x-coordinate of the public key
 * @param party_v_info
 *  The x-coordinate of the other party's public key
 * @param size_in_bits
 *  The number of bits of the key stream to be generated
 * @param result_key
 *  The buffer to write the generated key stream
 * @return
 *  TPM2_RC_SUCCESS on success
 */
TSS2_RC tpm2_kdfe(
        TPMI_ALG_HASH hash_alg, TPM2B_ECC_PARAMETER *Z,
        const unsigned char *label, int label_length,
        TPM2B_ECC_PARAMETER *party_u_info, TPM2B_ECC_PARAMETER *party_v_info,
        UINT16 size_in_bits, TPM2B_MAX_BUFFER  *result_key );

/**
 * Derive the seed value and protected seed value, as specified
 * in Appendix C.6.3 of TPM 2.0 Library Specification Part1
 *  (https://trustedcomputinggroup.org/resource/tpm-library-specification/)
 *
 * @param[in] parent_pub
 *  The parents ECC public key.
 * @param[in] label
 *  The label value. ie. "DUPLICATE\0" or "IDENTITY\0".
 * @param[in] label_len
 *  Length of the label.
 * @param[out] seed
 *  The derived seed value
 * @param[out] out_sym_seed
 *  protedted seed value, ie the public key for the ephemeral key.
 * @return
 *  True on success, false otherwise.
 */
bool ecdh_derive_seed_and_encrypted_seed(
        TPM2B_PUBLIC *parent_pub, const unsigned char *label, int label_len,
        TPM2B_DIGEST *seed, TPM2B_ENCRYPTED_SECRET *out_sym_seed);


#endif /* SRC_TPM_KDFE_H_ */
