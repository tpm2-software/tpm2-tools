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

#include <sapi/tpm20.h>

#include <openssl/err.h>
#include <openssl/hmac.h>

#include "log.h"
#include "tpm2_openssl.h"
#include "tpm2_util.h"

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

static inline const char *get_openssl_err(void) {
    return ERR_error_string(ERR_get_error(), NULL);
}

bool tpm2_openssl_hash_pcr_values(TPMI_ALG_HASH halg,
        TPML_DIGEST *digests, TPM2B_DIGEST *digest) {

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

    size_t i;
    for (i=0; i < digests->count; i++) {

        TPM2B_DIGEST *b = &digests->digests[i];
        rc = EVP_DigestUpdate(mdctx, b->buffer, b->size);
        if (!rc) {
            LOG_ERR("%s", get_openssl_err());
            goto out;
        }
    }

    unsigned size = EVP_MD_size(EVP_sha256());

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

HMAC_CTX *tpm2_openssl_hmac_new() {
    HMAC_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER) /* OpenSSL 1.1.0 */
    ctx = malloc(sizeof(*ctx));
#else
    ctx = HMAC_CTX_new();
#endif
    if (!ctx)
        return NULL;

#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER)
    HMAC_CTX_init(ctx);
#endif

    return ctx;
}

void tpm2_openssl_hmac_free(HMAC_CTX *ctx) {
#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER)
    HMAC_CTX_cleanup(ctx);
    free(ctx);
#else
    HMAC_CTX_free(ctx);
#endif
}
