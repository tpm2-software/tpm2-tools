//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
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
//**********************************************************************;

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#define BASE_DEFAULT_ATTRS \
    (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT)

#define DEFAULT_NAME_ALG TPM2_ALG_SHA256

typedef struct tpm_loadexternal_ctx tpm_loadexternal_ctx;
struct tpm_loadexternal_ctx {
    char *context_file_path;
    TPMI_RH_HIERARCHY hierarchy_value;
    TPM2_HANDLE handle;
    char *public_key_path; /* path to the public portion of an object */
    char *private_key_path; /* path to the private portion of an object */
    char *attrs; /* The attributes to use */
    char *auth; /* The password for use of the private portion */
    char *policy; /* a policy for use of the private portion */
    char *name_alg; /* name hashing algorithm */
};

static tpm_loadexternal_ctx ctx = {
    /*
     * default to the NULL hierarchy, as the tpm rejects loading a private
     * portion of an object in other hierarchies.
     */
    .hierarchy_value = TPM2_RH_NULL,
};

static bool load_external(TSS2_SYS_CONTEXT *sapi_context, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv, bool has_priv) {

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_NAME nameExt = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_LoadExternal(sapi_context, NULL,
            has_priv ? priv : NULL, pub,
            ctx.hierarchy_value, &ctx.handle, &nameExt,
            &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_LoadExternal, rval);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch(key) {
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy_value,
                   TPM2_HIERARCHY_FLAGS_ALL);
        if (!result) {
            return false;
        }
        break;
    case 'u':
        ctx.public_key_path = value;
        break;
    case 'r':
        ctx.private_key_path = value;
        break;
    case 'o':
        ctx.context_file_path = value;
        break;
    case 'A':
        ctx.attrs = value;
        break;
    case 'p':
        ctx.auth = value;
        break;
    case 'L':
        ctx.policy = value;
        break;
    case 'g':
        ctx.name_alg = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",          required_argument, NULL, 'a'},
      { "pubfile",            required_argument, NULL, 'u'},
      { "privfile",           required_argument, NULL, 'r'},
      { "out-context",        required_argument, NULL, 'o'},
      { "object-attributes",  required_argument, NULL, 'A'},
      { "policy-file",        required_argument, NULL, 'L'},
      { "auth-key",           required_argument, NULL, 'p'},
      { "halg",               required_argument, NULL, 'g'},
      { "auth-parent",        required_argument, NULL, 'P'},
    };

    *opts = tpm2_options_new("a:u:r:o:A:p:L:g:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

static bool load_private_RSA_from_key(RSA *k, TPM2B_SENSITIVE *priv) {

    const BIGNUM *p; /* the private key exponent */

#if OPENSSL_VERSION_NUMBER < 0x1010000fL /* OpenSSL 1.1.0 */
    p = k->p;
#else
    RSA_get0_factors(k, &p, NULL);
#endif

    TPMT_SENSITIVE *sa = &priv->sensitiveArea;

    sa->sensitiveType = TPM2_ALG_RSA;

    TPM2B_PRIVATE_KEY_RSA *pkr = &sa->sensitive.rsa;

    unsigned priv_bytes = BN_num_bytes(p);
    if (priv_bytes > sizeof(pkr->buffer)) {
        LOG_ERR("Expected prime \"d\" to be less than or equal to %zu,"
                " got: %u", sizeof(pkr->buffer), priv_bytes);
        return false;
    }

    pkr->size = priv_bytes;

    int success = BN_bn2bin(p, pkr->buffer);
    if (!success) {
        ERR_print_errors_fp (stderr);
        LOG_ERR("Could not copy private exponent \"d\"");
        return false;
    }

    return true;
}

static bool load_public_RSA_from_key(RSA *k, TPM2B_PUBLIC *pub) {

    TPMT_PUBLIC *pt = &pub->publicArea;
    pt->type = TPM2_ALG_RSA;

    TPMS_RSA_PARMS *rdetail = &pub->publicArea.parameters.rsaDetail;
    rdetail->scheme.scheme = TPM2_ALG_NULL;
    rdetail->symmetric.algorithm = TPM2_ALG_NULL;

    const BIGNUM *n; /* modulus */
    const BIGNUM *e; /* public key exponent */

#if OPENSSL_VERSION_NUMBER < 0x1010000fL /* OpenSSL 1.1.0 */
    n = k->n;
    e = k->e;
#else
    RSA_get0_key(k, &n, &e, NULL);
#endif

    /*
     * The size of the modulus is the key size in RSA, store this as the
     * keyBits in the RSA details.
     */
    rdetail->keyBits = BN_num_bytes(n) * 8;
    switch (rdetail->keyBits) {
    case 1024: /* falls-through */
    case 2048: /* falls-through */
    case 4096: /* falls-through */
        break;
    default:
        LOG_ERR("RSA key-size %u is not supported", rdetail->keyBits);
        return false;
    }

    /* copy the modulus to the unique RSA field */
    pt->unique.rsa.size = rdetail->keyBits/8;
    int success = BN_bn2bin(n, pt->unique.rsa.buffer);
    if (!success) {
        LOG_ERR("Could not copy public modulus N");
        return false;
    }

    /*Make sure that we can fit the exponent into a UINT32 */
    unsigned e_size = BN_num_bytes(e);
    if (e_size > sizeof(rdetail->exponent)) {
        LOG_ERR("Exponent is too big. Got %d expected less than or equal to %zu",
                e_size, sizeof(rdetail->exponent));
        return false;
    }

    /*
     * Copy the exponent into the field.
     * Returns 1 on success false on error.
     */
    return BN_bn2bin(e, (unsigned char *)&rdetail->exponent);
}

static bool load_public_RSA_from_pem(const char *path, TPM2B_PUBLIC *pub) {

    /*
     * Public PEM files appear in two formats:
     * 1. PEM format, read with PEM_read_RSA_PUBKEY
     * 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     *
     * See:
     *  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    FILE *f = fopen(path, "r");
    RSA *k = PEM_read_RSA_PUBKEY(f, NULL,
        NULL, NULL);
    if (!k) {
        k = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
    }
    fclose(f);
    if (!k) {
         ERR_print_errors_fp (stderr);
         LOG_ERR("Reading public PEM file \"%s\" failed", path);
         return false;
    }

    bool result = load_public_RSA_from_key(k, pub);

    RSA_free(k);

    return result;
}

static bool is_path_pem(const char *path) {

    unsigned char buf[4096];
    UINT16 size = sizeof(buf);

    bool result = files_load_bytes_from_path(path, buf, &size);
    if (!result) {
        return false;
    }

    static const char compareto[] = "-----BEGIN";

    return size > (sizeof(compareto) - 1)
           && !memcmp(buf, compareto, (sizeof(compareto) - 1));
}

static bool load_public(const char *path, TPM2B_PUBLIC *pub) {

    if (is_path_pem(path)) {
        return load_public_RSA_from_pem(path, pub);
    }

    return files_load_public(path, pub);
}

static int load_private_RSA_from_pem(const char *path, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    RSA *k = NULL;

    int rc = 0;

    FILE *fk = fopen(path, "r");
    if (!fk) {
        LOG_ERR("Could not open file \"%s\", error: %s",
                path, strerror(errno));
        return 0;
    }

    k = PEM_read_RSAPrivateKey(fk, NULL,
        NULL, NULL);
    fclose(fk);
    if (!k) {
         ERR_print_errors_fp (stderr);
         LOG_ERR("Reading PEM file \"%s\" failed", path);
         return 0;
    }

    bool loaded_priv = load_private_RSA_from_key(k, priv);
    if (!loaded_priv) {
        goto out;
    } else {
        rc |= 0x1;
    }

    bool loaded_pub = load_public_RSA_from_key(k, pub);
    if (!loaded_pub) {
        goto out;
    } else {
        rc |= 0x2;
    }

out:
    RSA_free(k);

    return rc;
}

/**
 * Loads a private portion of a key, and possibley the public portion, as RSA public data is in
 * a private pem file.
 *
 * @param path
 *  The path to load from.
 * @param pub
 *  The public structure to populate.
 * @param priv
 *  The sensitive structure to populate.
 *
 * @returns
 *  0 - error
 *  1 - loaded private
 *  2 - loaded public
 *  3 - loaded both
 */
static int load_private(const char *path, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    /*
     * load a PEM format private structure
     */
    if (is_path_pem(path)) {
        /*
         * returns the 0,1,2,3 scheme.
         */
        return load_private_RSA_from_pem(path, pub, priv);
    }

    return 0;
}

static inline bool did_load_public(int load_count) {
    return (load_count & 0x2);
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result;

    if (!ctx.public_key_path && !ctx.private_key_path) {
        LOG_ERR("Expected either -r or -u options");
        return false;
    }

    /*
     * Modifying this init to anything NOT 0 requires
     * the memset/reinit on the case of specified -u
     * and found public data in private.
     */
    TPM2B_PUBLIC pub = {
        . size = 0,
        .publicArea = {
            .authPolicy = { .size = 0 },
        },
    };

    /*
     * set up the public attributes with a default.
     * This can be cleared by load_public() if a TSS
     * object is provided.
     */
    if (ctx.attrs) {
        result = tpm2_attr_util_obj_from_optarg(ctx.attrs,
            &pub.publicArea.objectAttributes);
        if (!result) {
            return 1;
        }
    } else {
        /*
         * Default to the BASE attributes, but add in USER_WITH_AUTH if -p is specified
         * or NO -L. Where -L is a specified policy and -p is a specified password.
         * Truth Table:
         * -L -p | Result
         * --------------
         *  0  0 | 1 (set USER_WITH_AUTH)
         *  0  1 | 0 (don't set USER_WITH_AUTH) <-- we want this case.
         *  1  0 | 1
         *  1  1 | 1
         *
         * This is an if/then truth table, we want to execute setting USER_WITH_AUTH on
         * it's negation.
         */
        pub.publicArea.objectAttributes = BASE_DEFAULT_ATTRS;
        if (!(ctx.policy && !ctx.auth)) {
            pub.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
        }
    }

    /*
     * Set the policy for public, again this can be overridden if the
     * object is a TSS object
     */
    if (ctx.policy) {
        pub.publicArea.authPolicy.size = sizeof(pub.publicArea.authPolicy.buffer);
        bool res = files_load_bytes_from_path(ctx.policy,
                    pub.publicArea.authPolicy.buffer, &pub.publicArea.authPolicy.size);
        if (!res) {
            return false;
        }
    }

    /*
     * Set the name alg, again this gets wipped on a TSS object
     */
    pub.publicArea.nameAlg =
        ctx.name_alg ? tpm2_alg_util_from_optarg(ctx.name_alg, tpm2_alg_util_flags_hash
                |tpm2_alg_util_flags_misc) : DEFAULT_NAME_ALG;
    if (pub.publicArea.nameAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid name hashing algorithm, got: \"%s\"", ctx.name_alg);
        return 1;
    }

    /*
     * Set the AUTH value for sensitive portion
     */
    TPM2B_SENSITIVE priv = {
        .size = 0,
        .sensitiveArea = {
            /* no parent seed value for protection */
            .seedValue = { .size = 0 },
            .authValue = { .size = 0 }
        },
    };

    if (ctx.auth) {
        TPMS_AUTH_COMMAND tmp;
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.auth, &tmp, NULL);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.auth);
            return 1;
        }

        priv.sensitiveArea.authValue = tmp.hmac;
    }

    int load_count = 0;
    if (ctx.private_key_path) {
        load_count = load_private(ctx.private_key_path, &pub, &priv);
        if (!load_count) {
            return 1;
        }
    }

    /*
     * If we cannot load the public from the private and a path
     * is not specified for public, this is an error.
     *
     * If we loaded the public from the private and a public was
     * specified, this is warning. re-init public and load the
     * specified one.
     */
    if (!did_load_public(load_count) && !ctx.public_key_path) {
        LOG_ERR("Only loaded a private key, expected public key in either"
                " private PEM or -r option");
        return 1;
    } else if(did_load_public(load_count) && ctx.public_key_path) {
        LOG_WARN("Loaded a public key from the private portion"
                 " and a public portion was specified via -u. Defaulting"
                 " to specified public");

        memset(&pub.publicArea.parameters, 0, sizeof(pub.publicArea.parameters));
        pub.publicArea.type = TPM2_ALG_NULL;
    }

    if (ctx.public_key_path) {
        result = load_public(ctx.public_key_path, &pub);
        if (!result) {
            return 1;
        }
    }

    result = load_external(sapi_context, &pub, &priv, ctx.private_key_path != NULL);
    if (!result) {
        return 1;
    }

    tpm2_tool_output("0x%X\n", ctx.handle);

    if(ctx.context_file_path) {
        return files_save_tpm_context_to_path(sapi_context, ctx.handle,
                   ctx.context_file_path) != true;
    }

    return 0;
}
