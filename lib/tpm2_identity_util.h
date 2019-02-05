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
        TPM2B_PUBLIC *parent_pub,
        TPM2B_NAME *pubname,
        TPM2B_DIGEST *protection_seed,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key);

/**
 * Encrypts seed with parent public key for TPM2 credential protection process.
 *
 * @param protection_seed
 *  The identity structure protection seed that is to be encrypted.
 * @param parent_pub
 *  The public key used for encryption.
 * @param label
 *  Indicates label for the seed, such as "IDENTITY" or "DUPLICATE".
 * @param labelLen
 *  Length of label.
 * @param encrypted_protection_seed
 *  The encrypted protection seed to populate.
 * @return
 *  True on success, false on failure.
 */
bool tpm2_identity_util_encrypt_seed_with_public_key(
        TPM2B_DIGEST *protection_seed,
        TPM2B_PUBLIC *parent_pub,
        unsigned char *label,
        int labelLen,
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
bool tpm2_identity_util_calculate_inner_integrity(
        TPMI_ALG_HASH name_alg,
        TPM2B_SENSITIVE *sensitive,
        TPM2B_NAME *pubname,
        TPM2B_DATA *enc_sensitive_key,
        TPMT_SYM_DEF_OBJECT *sym_alg,
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
void tpm2_identity_util_calculate_outer_integrity(
        TPMI_ALG_HASH parent_name_alg,
        TPM2B_NAME *pubname,
        TPM2B_MAX_BUFFER *marshalled_sensitive,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac);

#endif /* LIB_TPM2_IDENTITY_UTIL_H_ */
