//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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

#ifndef LIB_TPM2_OPENSSL_H_
#define LIB_TPM2_OPENSSL_H_

#include <tss2/tss2_sys.h>

#include <openssl/err.h>
#include <openssl/hmac.h>

/**
 * Function prototype for a hashing routine.
 *
 * This is a wrapper around OSSL SHA256|384 and etc digesters.
 *
 * @param d
 *  The data to digest.
 * @param n
 *  The length of the data to digest.
 * @param md
 *  The output message digest.
 * @return
 * A pointer to the digest or NULL on error.
 */
typedef unsigned char *(*digester)(const unsigned char *d, size_t n, unsigned char *md);

/**
 * Get an openssl message digest from a tpm hashing algorithm.
 * @param algorithm
 *  The tpm algorithm to get the corresponding openssl version of.
 * @return
 *  A pointer to a message digester or NULL on failure.
 */
const EVP_MD *tpm2_openssl_halg_from_tpmhalg(TPMI_ALG_HASH algorithm);

/**
 * Start an openssl hmac session.
 * @return
 *  A valid session pointer or NULL on error.
 */
HMAC_CTX *tpm2_openssl_hmac_new();

/**
 * Free an hmac context created via tpm2_openssl_hmac_new().
 * @param ctx
 *  The context to release resources of.
 */
void tpm2_openssl_hmac_free(HMAC_CTX *ctx);

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
bool tpm2_openssl_hash_pcr_values(TPMI_ALG_HASH halg,
        TPML_DIGEST *digests, TPM2B_DIGEST *digest);

/**
 * Obtains an OpenSSL EVP_CIPHER_CTX dealing with version
 * API changes in OSSL.
 *
 * @return
 *  An Initialized OpenSSL EVP_CIPHER_CTX.
 */
EVP_CIPHER_CTX *tpm2_openssl_cipher_new(void);

/**
 * Free's an EVP_CIPHER_CTX obtained via tpm2_openssl_cipher_new()
 * dealing with OSSL API version changes.
 * @param ctx
 *  The EVP_CIPHER_CTX to free.
 */
void tpm2_openssl_cipher_free(EVP_CIPHER_CTX *ctx);

/**
 * Returns a function pointer capable of performing the
 * given digest from a TPMI_HASH_ALG.
 *
 * @param halg
 *  The hashing algorithm to use.
 * @return
 *  NULL on failure or a valid digester on success.
 */
digester tpm2_openssl_halg_to_digester(TPMI_ALG_HASH halg);

typedef enum tpm2_openssl_load_rc tpm2_openssl_load_rc;
enum tpm2_openssl_load_rc {
    lprc_error     = 0,      /* an error has occurred */
    lprc_private   = 1 << 0, /* successfully loaded a private portion of object */
    lprc_public    = 1 << 1, /* successfully loaded a public portion of object */
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
static inline bool tpm2_openssl_did_load_public(tpm2_openssl_load_rc load_status) {
    return (load_status & lprc_public);
}

/**
 * Loads a private portion of a key, and possibly the public portion.
 * For asymmetric algorithms the public data is in  private PEM file.
 * For symmetric keys, the file type is raw. For asymmetric keys, the
 * file type is a PEM file.
 *
 * This ONLY supports AES and RSA.
 *
 * It populates the sensitive seed with a random value for symmetric keys.
 *
 * @param path
 *  The path to load from.
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
tpm2_openssl_load_rc tpm2_openssl_load_private(const char *path, TPMI_ALG_PUBLIC alg,
        TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv);

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
bool tpm2_openssl_load_public(const char *path, TPMI_ALG_PUBLIC alg, TPM2B_PUBLIC *pub);

#endif /* LIB_TPM2_OPENSSL_H_ */
