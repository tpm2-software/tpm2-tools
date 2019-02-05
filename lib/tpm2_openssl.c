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

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
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
