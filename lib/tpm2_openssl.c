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

#include <stdlib.h>
#include <stdbool.h>
#include <openssl/pem.h>

#include "log.h"
#include "tpm_kdfa.h"
#include "tpm2_openssl.h"

int tpm2_openssl_halgid_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return NID_sha1;
    case TPM2_ALG_SHA256:
        return NID_sha256;
    case TPM2_ALG_SHA384:
        return NID_sha384;
    case TPM2_ALG_SHA512:
        return NID_sha512;
    default:
        return NID_sha256;
    }
    /* no return, not possible */
}

const EVP_MD *tpm2_openssl_halg_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
    /* no return, not possible */
}

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {

    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL)) {
        return 0;
    }

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }

    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }

    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
#endif

static inline const char *get_openssl_err(void) {
    return ERR_error_string(ERR_get_error(), NULL);
}


EVP_CIPHER_CTX *tpm2_openssl_cipher_new(void) {
    EVP_CIPHER_CTX *ctx;
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    ctx = malloc(sizeof(*ctx));
#else
    ctx = EVP_CIPHER_CTX_new();
#endif
    if (!ctx)
        return NULL;

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    EVP_CIPHER_CTX_init(ctx);
#endif

    return ctx;
}

void tpm2_openssl_cipher_free(EVP_CIPHER_CTX *ctx) {
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
}

bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg,
        BYTE *buffer, UINT16 length, TPM2B_DIGEST *digest) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", get_openssl_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", get_openssl_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, buffer, length);
    if (!rc) {
        LOG_ERR("%s", get_openssl_err());
        goto out;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        LOG_ERR("%s", get_openssl_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

// show all PCR banks according to g_pcrSelection & g_pcrs->
bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hashAlg, 
                TPML_PCR_SELECTION *pcrSelect, 
                tpm2_pcrs *pcrs, TPM2B_DIGEST *digest) {

    UINT32 vi = 0, di = 0, i;
    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(hashAlg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", get_openssl_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", get_openssl_err());
        goto out;
    }

    // Loop through all PCR/hash banks 
    for (i = 0; i < pcrSelect->count; i++) {

        // Loop through all PCRs in this bank
        UINT8 pcr_id;
        for (pcr_id = 0; pcr_id < pcrSelect->pcrSelections[i].sizeofSelect * 8; pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(&pcrSelect->pcrSelections[i],
                    pcr_id)) {
                // skip non-selected banks
                continue;
            }
            if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                goto out;
            }

            // Update running digest (to compare with quote)
            TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
            rc = EVP_DigestUpdate(mdctx, b->buffer, b->size);
            if (!rc) {
                LOG_ERR("%s", get_openssl_err());
                goto out;
            }

            if (++di < pcrs->pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < pcrs->count) {
                continue;
            }
        }
    }

    // Finalize running digest
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        LOG_ERR("%s", get_openssl_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

digester tpm2_openssl_halg_to_digester(TPMI_ALG_HASH halg) {

    switch(halg) {
    case TPM2_ALG_SHA1:
        return SHA1;
    case TPM2_ALG_SHA256:
        return SHA256;
    case TPM2_ALG_SHA384:
        return SHA384;
    case TPM2_ALG_SHA512:
        return SHA512;
    /* no default */
    }

    return NULL;
}

/*
 * Per man openssl(1), handle the following --passin formats:
 *     pass:password
 *             the actual password is password. Since the password is visible to utilities (like 'ps' under Unix) this form should only be used where security is not
 *             important.
 *
 *   env:var   obtain the password from the environment variable var. Since the environment of other processes is visible on certain platforms (e.g. ps under certain
 *             Unix OSes) this option should be used with caution.
 *
 *   file:pathname
 *             the first line of pathname is the password. If the same pathname argument is supplied to -passin and -passout arguments then the first line will be used
 *             for the input password and the next line for the output password. pathname need not refer to a regular file: it could for example refer to a device or
 *             named pipe.
 *
 *   fd:number read the password from the file descriptor number. This can be used to send the data via a pipe for example.
 *
 *   stdin     read the password from standard input.
 *
 */

typedef bool (*pfn_ossl_pw_handler)(const char *passin, char **pass);


RSA *tpm2_openssl_get_public_RSA_from_pem(FILE *f, const char *path) {

    /*
     * Public PEM files appear in two formats:
     * 1. PEM format, read with PEM_read_RSA_PUBKEY
     * 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     *
     * See:
     *  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    RSA *pub = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
    if (!pub) {
        pub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
    }

    if (!pub) {
         ERR_print_errors_fp (stderr);
         LOG_ERR("Reading public PEM file \"%s\" failed", path);
         return NULL;
    }

    return pub;
}
