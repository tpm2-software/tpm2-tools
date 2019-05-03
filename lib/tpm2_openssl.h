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
#include <openssl/rsa.h>

#include "pcr.h"

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) /* OpenSSL 1.1.0 */
#define LIB_TPM2_OPENSSL_OPENSSL_PRE11
#endif


#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
#endif


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
const EVP_MD *tpm2_openssl_halg_from_tpmhalg(TPMI_ALG_HASH algorithm);

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
bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg,
        BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest);

/**
 * Hash a list of PCR digests, supporting multiple banks.
 * @param halg
 *  The hashing algorithm to use.
 * @param pcrSelect
 *  The list that specifies which PCRs are selected.
 * @param pcrs
 *  The list of PCR banks, each containing a list of PCR digests to hash.
^ * @param digest
^ *  The result of hashing digests with halg.
 * @return
 *  true on success, false on error.
 */
bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hashAlg, 
        TPML_PCR_SELECTION *pcrSelect, 
        tpm2_pcrs *pcrs, TPM2B_DIGEST *digest);

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
 * Retrieves a public portion of an RSA key from a PEM file.
 *
 * @param f
 *  The FILE object that is open for reading the path.
 * @param path
 *  The path to load from.
 * @return
 *  The public structure.
 */
RSA* tpm2_openssl_get_public_RSA_from_pem(FILE *f, const char *path);

#endif /* LIB_TPM2_OPENSSL_H_ */
