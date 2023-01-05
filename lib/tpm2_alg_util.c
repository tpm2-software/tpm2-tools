/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_errata.h"
#include "tpm2_hash.h"
#include "tpm2_policy.h"

typedef struct alg_pair alg_pair;
struct alg_pair {
    const char *name;
    TPM2_ALG_ID id;
    tpm2_alg_util_flags flags;
    tpm2_alg_util_flags _flags;
};

typedef enum alg_iter_res alg_iter_res;
enum alg_iter_res {
    stop,
    go,
    found
};

typedef enum alg_parser_rc alg_parser_rc;
enum alg_parser_rc {
    alg_parser_rc_error,
    alg_parser_rc_continue,
    alg_parser_rc_done
};

typedef alg_iter_res (*alg_iter)(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata);

static void tpm2_alg_util_for_each_alg(alg_iter iterator, void *userdata) {

    static const alg_pair algs[] = {

        // Asymmetric
        { .name = "rsa", .id = TPM2_ALG_RSA, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },
        { .name = "ecc", .id = TPM2_ALG_ECC, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },

        // Symmetric
        { .name = "tdes", .id = TPM2_ALG_TDES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "aes", .id = TPM2_ALG_AES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "camellia", .id = TPM2_ALG_CAMELLIA, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "sm4", .id = TPM2_ALG_SM4, .flags = tpm2_alg_util_flags_symmetric },

        // Hash
        { .name = "sha1", .id = TPM2_ALG_SHA1, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha256", .id = TPM2_ALG_SHA256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha384", .id = TPM2_ALG_SHA384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha512", .id = TPM2_ALG_SHA512, .flags = tpm2_alg_util_flags_hash },
        { .name = "sm3_256", .id = TPM2_ALG_SM3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_256", .id = TPM2_ALG_SHA3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_384", .id = TPM2_ALG_SHA3_384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_512", .id = TPM2_ALG_SHA3_512, .flags = tpm2_alg_util_flags_hash },

        // Keyed hash
        { .name = "hmac", .id = TPM2_ALG_HMAC, tpm2_alg_util_flags_keyedhash | tpm2_alg_util_flags_sig },
        { .name = "xor", .id = TPM2_ALG_XOR, tpm2_alg_util_flags_keyedhash },
        { .name = "cmac", .id = TPM2_ALG_CMAC, .flags = tpm2_alg_util_flags_sig },

        // Mask Generation Functions
        { .name = "mgf1", .id = TPM2_ALG_MGF1, .flags = tpm2_alg_util_flags_mgf },

        // Signature Schemes
        { .name = "rsassa", .id = TPM2_ALG_RSASSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "rsapss", .id = TPM2_ALG_RSAPSS, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdsa", .id = TPM2_ALG_ECDSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdaa", .id = TPM2_ALG_ECDAA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecschnorr", .id = TPM2_ALG_ECSCHNORR, .flags = tpm2_alg_util_flags_sig },
        { .name = "sm2", .id = TPM2_ALG_SM2, .flags = tpm2_alg_util_flags_sig },

        // Asymmetric Encryption Scheme
        { .name = "oaep", .id = TPM2_ALG_OAEP, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "rsaes", .id = TPM2_ALG_RSAES, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "ecdh", .id = TPM2_ALG_ECDH, .flags = tpm2_alg_util_flags_enc_scheme },

        // Key derivation functions
        { .name = "kdf1_sp800_56a", .id = TPM2_ALG_KDF1_SP800_56A, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf2", .id = TPM2_ALG_KDF2, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf1_sp800_108", .id = TPM2_ALG_KDF1_SP800_108, .flags = tpm2_alg_util_flags_kdf },
        { .name = "ecmqv", .id = TPM2_ALG_ECMQV, .flags = tpm2_alg_util_flags_kdf },

        // Modes
        { .name = "ctr", .id = TPM2_ALG_CTR, .flags = tpm2_alg_util_flags_mode },
        { .name = "ofb", .id = TPM2_ALG_OFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "cbc", .id = TPM2_ALG_CBC, .flags = tpm2_alg_util_flags_mode },
        { .name = "cfb", .id = TPM2_ALG_CFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "ecb", .id = TPM2_ALG_ECB, .flags = tpm2_alg_util_flags_mode },

        { .name = "symcipher", .id = TPM2_ALG_SYMCIPHER, .flags = tpm2_alg_util_flags_base },
        { .name = "keyedhash", .id = TPM2_ALG_KEYEDHASH, .flags = tpm2_alg_util_flags_base },

        // Misc
        { .name = "null", .id = TPM2_ALG_NULL, .flags = tpm2_alg_util_flags_misc | tpm2_alg_util_flags_rsa_scheme },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(algs); i++) {
        const alg_pair *alg = &algs[i];
        alg_iter_res result = iterator(alg->id, alg->name, alg->flags,
                userdata);
        if (result != go) {
            return;
        }
    }
}

static alg_parser_rc handle_sym_common(const char *ext, TPMT_SYM_DEF_OBJECT *s, bool is_parent) {

    if (ext == NULL || ext[0] == '\0') {
        ext = "128";
    }

    if (!strncmp(ext, "128", 3)) {
        s->keyBits.sym = 128;
    } else if (!strncmp(ext, "192", 3)) {
        s->keyBits.sym = 192;
    } else if (!strncmp(ext, "256", 3)) {
        s->keyBits.sym = 256;
    } else {
        return alg_parser_rc_error;
    }

    ext += 3;

    if (*ext == '\0') {
        ext = is_parent ? "cfb" : "null";
    }

    s->mode.sym = tpm2_alg_util_strtoalg(ext,
            tpm2_alg_util_flags_mode | tpm2_alg_util_flags_misc);
    if (s->mode.sym == TPM2_ALG_ERROR) {
        return alg_parser_rc_error;
    }

    return alg_parser_rc_done;
}

/*
 * Macro for redundant code collapse in handle_asym_scheme_common
 * You cannot change all the variables in this, as they are dependent
 * on names in that routine; this is for simplicity.
 */
#define do_scheme_halg(scheme, advance, alg) \
    do { \
        scheme += advance; \
        s->scheme.scheme = alg; \
        do_scheme_hash_alg = true; \
        found = true; \
    } while (0)

static alg_parser_rc handle_scheme_sign(const char *scheme,
        TPM2B_PUBLIC *public) {

    char buf[256];

    if (!scheme || scheme[0] == '\0') {
        scheme = "null";
    }

    int rc = snprintf(buf, sizeof(buf), "%s", scheme);
    if (rc < 0 || (size_t) rc >= sizeof(buf)) {
        return alg_parser_rc_error;
    }

    // Get the scheme and symetric details
    TPMS_ASYM_PARMS *s = &public->publicArea.parameters.asymDetail;

    if (!strcmp(scheme, "null")) {
        public->publicArea.parameters.asymDetail.scheme.scheme = TPM2_ALG_NULL;
        return alg_parser_rc_continue;
    }

    char *halg = NULL;
    char *split = strchr(scheme, '-');
    if (split) {
        *split = '\0';
        halg = split + 1;
    }

    bool found = false;
    bool do_scheme_hash_alg = false;

    if (public->publicArea.type == TPM2_ALG_ECC) {
        if (!strncmp(scheme, "ecdsa", 5)) {
            do_scheme_halg(scheme, 5, TPM2_ALG_ECDSA);
        } else if (!strncmp(scheme, "ecdh", 4)) {
            do_scheme_halg(scheme, 4, TPM2_ALG_ECDH);
        } else if (!strncmp(scheme, "ecschnorr", 9)) {
            do_scheme_halg(scheme, 9, TPM2_ALG_ECSCHNORR);
        } else if (!strncmp(scheme, "sm2", 3)) {
            do_scheme_halg(scheme, 3, TPM2_ALG_SM2);
        } else if (!strncmp(scheme, "ecdaa", 5)) {
            do_scheme_halg(scheme, 5, TPM2_ALG_ECDAA);
            /*
             * ECDAA has both a commit-counter value and hashing algorithm.
             * The default commit-counter value is set to zero to use the first
             * commit-id.
             */
            if (scheme[0] == '\0') {
                scheme = "0";
            }

            TPMS_SIG_SCHEME_ECDAA *e = &s->scheme.details.ecdaa;

            bool res = tpm2_util_string_to_uint16(scheme, &e->count);
            if (!res) {
                return alg_parser_rc_error;
            }
        } else if (!strcmp("null", scheme)) {
            s->scheme.scheme = TPM2_ALG_NULL;
        }
    } else {
        if (!strcmp(scheme, "rsaes")) {
            /*
             * rsaes has no hash alg or details, so it MUST
             * match exactly, notice strcmp and NOT strNcmp!
             */
            s->scheme.scheme = TPM2_ALG_RSAES;
            found = true;
        } else if (!strcmp("null", scheme)) {
            s->scheme.scheme = TPM2_ALG_NULL;
            found = true;
        } else if (!strncmp("rsapss", scheme, 6)) {
            do_scheme_halg(scheme, 6, TPM2_ALG_RSAPSS);
        } else if (!strncmp("rsassa", scheme, 6)) {
            do_scheme_halg(scheme, 6, TPM2_ALG_RSASSA);
        } else if (!strncmp(scheme, "oaep", 4)) {
            do_scheme_halg(scheme, 4, TPM2_ALG_OAEP);
        }
    }

    /* If we're not expecting a hash alg then halg should be NULL */
    if ((!do_scheme_hash_alg && halg) || !found) {
        return alg_parser_rc_error;
    }

    /* if we're expecting a hash alg and none provided default */
    if (do_scheme_hash_alg && !halg) {
        halg = "sha256";
    }

    /*
     * If the scheme is set, both the encrypt and decrypt attributes cannot be set,
     * check to see if this is the case, and turn down:
     *  - DECRYPT - If its a signing scheme.
     *  - ENCRYPT - If its an asymmetric enc scheme.
     */
    if (s->scheme.scheme != TPM2_ALG_NULL) {
        bool is_both_set = !!(public->publicArea.objectAttributes
                & (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT));
        if (is_both_set) {
            tpm2_alg_util_flags flags = tpm2_alg_util_algtoflags(
                    s->scheme.scheme);
            TPMA_OBJECT turn_down_flags =
                    (flags & tpm2_alg_util_flags_sig) ?
                            TPMA_OBJECT_DECRYPT : TPMA_OBJECT_SIGN_ENCRYPT;
            public->publicArea.objectAttributes &= ~turn_down_flags;
        }
    }

    if (do_scheme_hash_alg) {
    public->publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg =
                tpm2_alg_util_strtoalg(halg, tpm2_alg_util_flags_hash);
        if (public->publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg
                == TPM2_ALG_ERROR) {
            return alg_parser_rc_error;
        }
    }

    return alg_parser_rc_continue;
}

static alg_parser_rc handle_rsa(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_RSA;
    TPMS_RSA_PARMS *r = &public->publicArea.parameters.rsaDetail;
    r->exponent = 0;

    size_t len = ext ? strlen(ext) : 0;
    if (len == 0 || ext[0] == '\0') {
        ext = "2048";
    }

    // Deal with bit size
    if (!strncmp(ext, "1024", 4)) {
        r->keyBits = 1024;
        ext += 4;
    } else if (!strncmp(ext, "2048", 4)) {
        r->keyBits = 2048;
        ext += 4;
    } else if (!strncmp(ext, "4096", 4)) {
        r->keyBits = 4096;
        ext += 4;
    } else if (!strncmp(ext, "3072", 4)) {
        r->keyBits = 3072;
        ext += 4;
    } else {
        r->keyBits = 2048;
    }

    /* rsa extension should be consumed at this point */
    return ext[0] == '\0' ? alg_parser_rc_continue : alg_parser_rc_error;
}

static alg_parser_rc handle_ecc(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_ECC;

    TPMS_ECC_PARMS *e = &public->publicArea.parameters.eccDetail;
    e->kdf.scheme = TPM2_ALG_NULL;
    e->curveID = TPM2_ECC_NONE;

    /* handle default ecc curve (NIST_P256) */
    if (ext == NULL || ext[0] == '\0') {
        e->curveID = TPM2_ECC_NIST_P256;
        return alg_parser_rc_continue;
    }

    if (ext[0] == '_') {
        /* skip separator */
        ext++;
        if (!strcmp(ext, "sm2_p256") || !strcmp(ext, "sm2")) {
            e->curveID = TPM2_ECC_SM2_P256;
            return alg_parser_rc_continue;
        } else if (strncmp(ext, "nist_p", 6)) {
            return alg_parser_rc_error;
        }
        ext += 6;
        if (ext[0] == '\0') {
            return alg_parser_rc_error;
        }
        /* fall through to NIST curves */
    }

    /* parse NIST curves */
    if (!strncmp(ext, "192", 3)) {
        e->curveID = TPM2_ECC_NIST_P192;
        ext += 3;
    } else if (!strncmp(ext, "224", 3)) {
        e->curveID = TPM2_ECC_NIST_P224;
        ext += 3;
    } else if (!strncmp(ext, "256", 3)) {
        e->curveID = TPM2_ECC_NIST_P256;
        ext += 3;
    } else if (!strncmp(ext, "384", 3)) {
        e->curveID = TPM2_ECC_NIST_P384;
        ext += 3;
    } else if (!strncmp(ext, "521", 3)) {
        e->curveID = TPM2_ECC_NIST_P521;
        ext += 3;
    }

    /* ecc extension should be consumed at this point */
    return ext[0] == '\0' ? alg_parser_rc_continue : alg_parser_rc_error;
}

static alg_parser_rc handle_aes(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_SYMCIPHER;

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
            &public->publicArea.objectAttributes);

    TPMT_SYM_DEF_OBJECT *s = &public->publicArea.parameters.symDetail.sym;
    s->algorithm = TPM2_ALG_AES;

    return handle_sym_common(ext, s, false);
}

static alg_parser_rc handle_camellia(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_SYMCIPHER;

    TPMT_SYM_DEF_OBJECT *s = &public->publicArea.parameters.symDetail.sym;
    s->algorithm = TPM2_ALG_CAMELLIA;

    return handle_sym_common(ext, s, false);
}

static alg_parser_rc handle_sm4(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_SYMCIPHER;

    TPMT_SYM_DEF_OBJECT *s = &public->publicArea.parameters.symDetail.sym;
    s->algorithm = TPM2_ALG_SM4;

    return handle_sym_common(ext, s, false);
}

static alg_parser_rc handle_xor(TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_KEYEDHASH;
    public->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_XOR;

    return alg_parser_rc_continue;
}

static alg_parser_rc handle_hmac(TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_KEYEDHASH;
    public->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;

    return alg_parser_rc_continue;
}

static alg_parser_rc handle_keyedhash(TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_KEYEDHASH;
    public->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    return alg_parser_rc_done;
}

static alg_parser_rc handle_object(const char *object, TPM2B_PUBLIC *public) {

    if (!strncmp(object, "rsa", 3)) {
        object += 3;
        return handle_rsa(object, public);
    } else if (!strncmp(object, "ecc", 3)) {
        object += 3;
        return handle_ecc(object, public);
    } else if (!strncmp(object, "aes", 3)) {
        object += 3;
        return handle_aes(object, public);
    } else if (!strncmp(object, "camellia", 8)) {
        object += 8;
        return handle_camellia(object, public);
    } else if (!strncmp(object, "sm4", 3)) {
        object += (object[3] == '_') ? 4 : 3;
        return handle_sm4(object, public);
    } else if (!strcmp(object, "hmac")) {
        return handle_hmac(public);
    } else if (!strcmp(object, "xor")) {
        return handle_xor(public);
    } else if (!strcmp(object, "keyedhash")) {
        return handle_keyedhash(public);
    }

    return alg_parser_rc_error;
}

static alg_parser_rc handle_scheme_keyedhash(const char *scheme,
        TPM2B_PUBLIC *public) {

    if (!scheme || scheme[0] == '\0') {
        scheme = "sha256";
    }

    TPM2_ALG_ID alg = tpm2_alg_util_strtoalg(scheme, tpm2_alg_util_flags_hash);
    if (alg == TPM2_ALG_ERROR) {
        return alg_parser_rc_error;
    }

    switch (public->publicArea.parameters.keyedHashDetail.scheme.scheme) {
    case TPM2_ALG_HMAC:
    public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
                alg;
        break;
    case TPM2_ALG_XOR:
    public->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf =
                TPM2_ALG_KDF1_SP800_108;
    public->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg =
                alg;
        break;
    default:
        return alg_parser_rc_error;
    }

    return alg_parser_rc_done;
}

static alg_parser_rc handle_scheme(const char *scheme, TPM2B_PUBLIC *public) {

    switch (public->publicArea.type) {
    case TPM2_ALG_RSA:
    case TPM2_ALG_ECC:
        return handle_scheme_sign(scheme, public);
    case TPM2_ALG_KEYEDHASH:
        return handle_scheme_keyedhash(scheme, public);
    default:
        return alg_parser_rc_error;
    }

    return alg_parser_rc_error;
}

static alg_parser_rc handle_asym_detail(const char *detail,
        TPM2B_PUBLIC *public) {

    bool is_restricted = !!(public->publicArea.objectAttributes
            & TPMA_OBJECT_RESTRICTED);
    bool is_rsapps = public->publicArea.parameters.asymDetail.scheme.scheme
            == TPM2_ALG_RSAPSS;

    switch (public->publicArea.type) {
    case TPM2_ALG_RSA:
    case TPM2_ALG_ECC:

        if (!detail || detail[0] == '\0') {
            detail = is_restricted || is_rsapps ? "aes128cfb" : "null";
        }

        TPMT_SYM_DEF_OBJECT *s = &public->publicArea.parameters.symDetail.sym;

        if (!strncmp(detail, "aes", 3)) {
            s->algorithm = TPM2_ALG_AES;
            return handle_sym_common(detail + 3, s, is_restricted);
        } else if (!strncmp(detail, "camellia", 8)) {
            s->algorithm = TPM2_ALG_CAMELLIA;
            return handle_sym_common(detail + 8, s, is_restricted);
        } else if (!strncmp(detail, "sm4", 3)) {
            s->algorithm = TPM2_ALG_SM4;
            detail += (detail[3] == '_') ? 4 : 3;
            return handle_sym_common(detail, s, is_restricted);
        } else if (!strcmp(detail, "null")) {
            s->algorithm = TPM2_ALG_NULL;
            return alg_parser_rc_done;
        }
        /* no default */
    }

    return alg_parser_rc_error;
}

bool tpm2_alg_util_handle_ext_alg(const char *alg_spec, TPM2B_PUBLIC *public) {

    char buf[256];

    if (!alg_spec) {
        return false;
    }

    int rc = snprintf(buf, sizeof(buf), "%s", alg_spec);
    if (rc < 0 || (size_t) rc >= sizeof(buf)) {
        goto error;
    }

    char *object = NULL;
    char *scheme = NULL;
    char *symdetail = NULL;

    char *b = buf;
    char *tok = NULL;
    char *saveptr = NULL;
    unsigned i = 0;
    while ((tok = strtok_r(b, ":", &saveptr))) {
        b = NULL;

        switch (i) {
        case 0:
            object = tok;
            break;
        case 1:
            scheme = tok;
            break;
        case 2:
            symdetail = tok;
            break;
        default:
            goto error;
        }
        i++;
    }

    if (i == 0) {
        goto error;
    }

    alg_parser_rc prc = handle_object(object, public);
    if (prc == alg_parser_rc_done) {
        /* we must have exhausted all the entries or it's an error */
        return scheme || symdetail ? false : true;
    }

    if (prc == alg_parser_rc_error) {
        return false;
    }

    /*
     * at this point we either have scheme or asym detail, if it
     * doesn't process as a scheme shuffle it to asym detail
     */
    for (i = 0; i < 2; i++) {
        prc = handle_scheme(scheme, public);
        if (prc == alg_parser_rc_done) {
            /* we must have exhausted all the entries or it's an error */
            return symdetail ? false : true;
        }

        if (prc == alg_parser_rc_error) {
            /*
             * if symdetail is set scheme must be consumed
             * unless scheme has been skipped by setting it
             * to NULL
             */
            if (symdetail && scheme) {
                return false;
            }

            symdetail = scheme;
            scheme = NULL;
            continue;
        }

        /* success in processing scheme */
        break;
    }

    /* handle asym detail */
    prc = handle_asym_detail(symdetail, public);
    if (prc != alg_parser_rc_done) {
        goto error;
    }

    return true;

    error:
    LOG_ERR("Could not handle algorithm spec: \"%s\"", alg_spec);
    return false;
}

tool_rc tpm2_alg_util_handle_rsa_ext_alg(const char *alg_spec,
    TPM2B_PUBLIC *public) {

    #define RSA_KEYBITS_STRLEN 6
    char *ext_alg_str = calloc(1, strlen(alg_spec) + strlen("rsa") +
        RSA_KEYBITS_STRLEN);
    if (ext_alg_str == NULL) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    strcat(ext_alg_str, "rsa");
    switch(public->publicArea.parameters.rsaDetail.keyBits) {
        case 1024: strcat(ext_alg_str, "1024:");
                   break;
        case 2048: strcat(ext_alg_str, "2048:");
                   break;
        case 3072: strcat(ext_alg_str, "3072:");
                   break;
        case 4096: strcat(ext_alg_str, "4096:");
                   break;
    };
    strcat(ext_alg_str, alg_spec);

    bool result = tpm2_alg_util_handle_ext_alg(ext_alg_str, public);
    free(ext_alg_str);

    return result ? tool_rc_success : tool_rc_general_error;
}

static alg_iter_res find_match(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata) {

    alg_pair *search_data = (alg_pair *) userdata;

    /*
     * if name, then search on name, else
     * search by id.
     */
    if (search_data->name && !strcmp(search_data->name, name)) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->id = id;
            search_data->_flags = flags;
        }
        return res;
    } else if (search_data->id == id) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->name = name;
            search_data->_flags = flags;
        }
        return res;
    }

    return go;
}

TPM2_ALG_ID tpm2_alg_util_strtoalg(const char *name, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = name, .id = TPM2_ALG_ERROR, .flags = flags };

    if (name) {
        tpm2_alg_util_for_each_alg(find_match, &userdata);
    }

    return userdata.id;
}

const char *tpm2_alg_util_algtostr(TPM2_ALG_ID id, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = NULL, .id = id, .flags = flags };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata.name;
}

const char *tpm2_alg_util_numtoalgstr(const char *str, tpm2_alg_util_flags flags) {
    TPM2_ALG_ID alg_id;

    if (tpm2_util_string_to_uint16(str, &alg_id)) {
        return tpm2_alg_util_algtostr(alg_id, flags);
    } else {
        return str;
    }
}

tpm2_alg_util_flags tpm2_alg_util_algtoflags(TPM2_ALG_ID id) {

    alg_pair userdata = { .name = NULL, .id = id, .flags =
            tpm2_alg_util_flags_any, ._flags = tpm2_alg_util_flags_none };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata._flags;
}

TPM2_ALG_ID tpm2_alg_util_from_optarg(const char *optarg,
        tpm2_alg_util_flags flags) {

    TPM2_ALG_ID halg;
    bool res = tpm2_util_string_to_uint16(optarg, &halg);
    if (!res) {
        halg = tpm2_alg_util_strtoalg(optarg, flags);
    } else {
        if (!tpm2_alg_util_algtostr(halg, flags)) {
            return TPM2_ALG_ERROR;
        }
    }
    return halg;
}

UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id) {

    switch (id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
        /* no default */
    }

    return 0;
}

static const char *hex_to_byte_err(int rc) {

    switch (rc) {
    case -2:
        return "String not even in length";
    case -3:
        return "Non hex digit found";
    case -4:
        return "Hex value too big for digest";
    }
    return "unknown";
}

bool pcr_parse_digest_list(char **argv, int len,
        tpm2_pcr_digest_spec *digest_spec) {

    /*
     * int is chosen because of what is passed in from main, avoids
     * sign differences.
     * */
    int i;
    for (i = 0; i < len; i++) {
        tpm2_pcr_digest_spec *dspec = &digest_spec[i];

        UINT32 count = 0;

        /*
         * Split <pcr index>:<hash alg>=<hash value>,... on : and separate with null byte, ie:
         * <pce index> '\0' <hash alg>'\0'<data>
         *
         * Start by splitting out the pcr index, and validating it.
         */
        char *spec_str = argv[i];
        char *pcr_index_str = spec_str;
        char *digest_spec_str = strchr(spec_str, ':');
        if (!digest_spec_str) {
            LOG_ERR("Expecting : in digest spec, not found, got: \"%s\"",
                    spec_str);
            return false;
        }

        *digest_spec_str = '\0';
        digest_spec_str++;

        bool result = pcr_get_id(pcr_index_str, &dspec->pcr_index);
        if (!result) {
            LOG_ERR("Got invalid PCR Index: \"%s\", in digest spec: \"%s\"",
                    pcr_index_str, spec_str);
            return false;
        }

        /* now that the pcr_index is removed, parse the remaining <hash_name>=<hash_value>,.. */
        char *digest_hash_tok;
        char *save_ptr = NULL;

        /* keep track of digests we have seen */

        while ((digest_hash_tok = strtok_r(digest_spec_str, ",", &save_ptr))) {
            digest_spec_str = NULL;

            if (count >= ARRAY_LEN(dspec->digests.digests)) {
                LOG_ERR("Specified too many digests per spec, max is: %zu",
                        ARRAY_LEN(dspec->digests.digests));
                return false;
            }

            TPMT_HA *d = &dspec->digests.digests[count];

            char *stralg = digest_hash_tok;
            char *split = strchr(digest_hash_tok, '=');
            if (!split) {
                LOG_ERR("Expecting = in <hash alg>=<hash value> spec, got: "
                        "\"%s\"", digest_hash_tok);
                return false;
            }
            *split = '\0';
            split++;

            char *data = split;

            /*
             * Convert and validate the hash algorithm. It should be a hash algorithm
             */
            TPM2_ALG_ID alg = tpm2_alg_util_from_optarg(stralg,
                    tpm2_alg_util_flags_hash);
            if (alg == TPM2_ALG_ERROR) {
                LOG_ERR("Could not convert algorithm, got: \"%s\"", stralg);
                return false;
            }

            d->hashAlg = alg;

            /* fill up the TPMT_HA structure with algorithm and digest */
            BYTE *digest_data = (BYTE *) &d->digest;

            UINT16 expected_hash_size = tpm2_alg_util_get_hash_size(alg);
            /* strip any preceding hex on the data as tpm2_util_hex_to_byte_structure doesn't support it */
            bool is_hex = !strncmp("0x", data, 2);
            if (is_hex) {
                data += 2;
            }

            UINT16 size = expected_hash_size;
            int rc = tpm2_util_hex_to_byte_structure(data, &size, digest_data);
            if (rc) {
                LOG_ERR("Error \"%s\" converting hex string as data, got:"
                        " \"%s\"", hex_to_byte_err(rc), data);
                return false;
            }

            if (expected_hash_size != size) {
                LOG_ERR("Algorithm \"%s\" expects a size of %u bytes, got: %u",
                        stralg, expected_hash_size, size);
                return false;
            }

            count++;
        }

        if (!count) {
            LOG_ERR("Missing or invalid <hash alg>=<hash value> spec for pcr:"
                    " \"%s\"", pcr_index_str);
            return false;
        }

        /* assign count at the end, so count is 0 on error */
        dspec->digests.count = count;
    }

    return true;
}

static tool_rc tpm2_public_to_scheme(ESYS_CONTEXT *ectx, ESYS_TR key, TPMI_ALG_PUBLIC *type,
        TPMT_SIG_SCHEME *sigscheme) {

    tool_rc rc = tool_rc_general_error;

    TPM2B_PUBLIC *out_public = NULL;
    rc = tpm2_readpublic(ectx, key, &out_public, NULL, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    *type = out_public->publicArea.type;
    TPMU_PUBLIC_PARMS *pp = &out_public->publicArea.parameters;

    /*
     * Symmetric ciphers do not have signature algorithms
     */
    if (*type == TPM2_ALG_SYMCIPHER) {
        LOG_ERR("Cannot convert symmetric cipher to signature algorithm");
        goto out;
    }

    /*
     * Now we are looking at specific algorithms that the keys
     * are bound to, so we need to populate that in the scheme
     */
    if ((*type == TPM2_ALG_RSA || *type == TPM2_ALG_ECC)) {

        sigscheme->scheme = pp->asymDetail.scheme.scheme;
        /* they all have a hash alg, and for most schemes' thats it */
        sigscheme->details.any.hashAlg
            = pp->asymDetail.scheme.details.anySig.hashAlg;

        rc = tool_rc_success;
        goto out;
    }

    /* keyed hash could be the only one left */
    sigscheme->scheme = pp->keyedHashDetail.scheme.scheme;
    sigscheme->details.hmac.hashAlg = pp->keyedHashDetail.scheme.details.hmac.hashAlg;

    rc = tool_rc_success;

out:
    Esys_Free(out_public);
    return rc;
}

static bool is_null_alg(TPM2_ALG_ID alg) {
    return !alg || alg == TPM2_ALG_NULL;
}

tool_rc tpm2_alg_util_get_signature_scheme(ESYS_CONTEXT *ectx,
        ESYS_TR key_handle, TPMI_ALG_HASH *halg, TPMI_ALG_SIG_SCHEME sig_scheme,
        TPMT_SIG_SCHEME *scheme) {

    TPMI_ALG_PUBLIC type = TPM2_ALG_NULL;
    TPMT_SIG_SCHEME object_sigscheme = { 0 };
    tool_rc rc = tpm2_public_to_scheme(ectx, key_handle, &type, &object_sigscheme);
    if (rc != tool_rc_success) {
        return rc;
    }

    LOG_INFO("hashing alg in: 0x%x", *halg);
    LOG_INFO("sig scheme in: 0x%x", sig_scheme);

    /*
     * if scheme is requested by the user, verify the scheme will work
     */
    if (!is_null_alg(sig_scheme) && !is_null_alg(object_sigscheme.scheme)
            && object_sigscheme.scheme != sig_scheme) {
        LOG_ERR("Requested sign scheme \"%s\" but object only supports sign scheme \%s\")",
                tpm2_alg_util_algtostr(sig_scheme, tpm2_alg_util_flags_any),
                tpm2_alg_util_algtostr(object_sigscheme.scheme, tpm2_alg_util_flags_any));
        return tool_rc_general_error;
    } else {
            /*
             * set a default for RSA, ECC or KEYEDHASH
             * Not ECDAA, it wasn't chosen because it needs count as well,
             * so any.hashAlg doesn't work. Aksim what would you pick for count?
             * See bug #2071 to figure out what to do if an ECDAA scheme comes back.
             *
             * Assign scheme based on type:
             * TPM2_ALG_RSA --> TPM2_ALG_RSSASSA
             * TPM2_ALG_ECC --> TPM2_ALG_ECDSA
             * TPM2_ALG_KEYEDHASH --> TPM2_ALG_HMAC
             */
        if (is_null_alg(sig_scheme)) {
            object_sigscheme.scheme = (type == TPM2_ALG_RSA) ? TPM2_ALG_RSASSA :
                (type == TPM2_ALG_ECC) ? TPM2_ALG_ECDSA : TPM2_ALG_HMAC;
        } else {
            object_sigscheme.scheme = sig_scheme;
        }
    }

    /* if hash alg is requested by the user, verify the hash alg will work */
    if (!is_null_alg(*halg) && !is_null_alg(object_sigscheme.details.any.hashAlg)
            && object_sigscheme.details.any.hashAlg != *halg) {
        LOG_ERR("Requested signature hash alg \"%s\" but object only supports signature hash alg \%s\")",
                tpm2_alg_util_algtostr(*halg, tpm2_alg_util_flags_any),
                tpm2_alg_util_algtostr(object_sigscheme.details.any.hashAlg, tpm2_alg_util_flags_any));
        return tool_rc_general_error;
    } else {
        object_sigscheme.details.any.hashAlg = is_null_alg(*halg) ? TPM2_ALG_SHA256 :
                *halg;
    }

    /* everything requested matches, or we got defaults move along */
    *halg = object_sigscheme.details.any.hashAlg;
    *scheme = object_sigscheme;

    LOG_INFO("halg out: 0x%x", *halg);
    LOG_INFO("sig scheme out: 0x%x", scheme->scheme);

    return tool_rc_success;
}

tool_rc tpm2_alg_util_public_init(const char *alg_details, const char *name_halg,
        char *attrs, char *auth_policy,  TPMA_OBJECT def_attrs,
        TPM2B_PUBLIC *public) {

    memset(public, 0, sizeof(*public));

    /* load a policy from a path if present */
    if (auth_policy) {
        tool_rc rc = tpm2_policy_set_digest(auth_policy,
                &public->publicArea.authPolicy);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    /* Set the hashing algorithm used for object name */
    public->publicArea.nameAlg = name_halg ?
        tpm2_alg_util_from_optarg(name_halg, tpm2_alg_util_flags_hash) :
        TPM2_ALG_SHA256;
    if (public->publicArea.nameAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid name hashing algorithm, got\"%s\"", name_halg);
        return tool_rc_unsupported;
    }

    /* Set specified attributes or use default */
    if (attrs) {
        bool res = tpm2_attr_util_obj_from_optarg(attrs,
                &public->publicArea.objectAttributes);
        if (!res) {
            return tool_rc_unsupported;
        }
    } else {
        public->publicArea.objectAttributes = def_attrs;
    }

    /*
     * Some defaults may not be OK with the specified algorithms, if their defaults,
     * tweak the Object Attributes, if specified by user, complain things will not
     * work together and suggest attributes. This allows the user to verify what the
     * want.
     */
    TPM2B_PUBLIC tmp = *public;
    bool res = tpm2_alg_util_handle_ext_alg(alg_details, &tmp);
    if (!res) {
        LOG_ERR("Could not handle algorithm: \"%s\"", alg_details);
        return tool_rc_unsupported;
    }

    if (attrs && tmp.publicArea.objectAttributes !=
        public->publicArea.objectAttributes) {

        char *proposed_attrs = tpm2_attr_util_obj_attrtostr(
                tmp.publicArea.objectAttributes);
        LOG_ERR("Specified attributes \"%s\" and algorithm specifier \"%s\" do "
                "not work together, try attributes: \"%s\"", attrs, alg_details,
                proposed_attrs);
        free(proposed_attrs);
        return tool_rc_unsupported;
    }

    *public = tmp;

    return tool_rc_success;
}

const char *tpm2_alg_util_ecc_to_str(TPM2_ECC_CURVE curve_id) {

    switch (curve_id) {
    case TPM2_ECC_NIST_P192:
        return "NIST p192";
    case TPM2_ECC_NIST_P224:
        return "NIST p224";
    case TPM2_ECC_NIST_P256:
        return "NIST p256";
    case TPM2_ECC_NIST_P384:
        return "NIST p384";
    case TPM2_ECC_NIST_P521:
        return "NIST 521";
    case TPM2_ECC_BN_P256:
        return "BN P256";
    case TPM2_ECC_BN_P638:
        return "BN P638";
    case TPM2_ECC_SM2_P256:
        return "SM2 p256";
        /* no default */
    }
    return NULL;
}

bool tpm2_alg_util_is_aes_size_valid(UINT16 size_in_bytes) {

    switch (size_in_bytes) {
    case 16:
    case 24:
    case 32:
        return true;
    default:
        LOG_ERR("Invalid AES key size, got %u bytes, expected 16,24 or 32",
                size_in_bytes);
        return false;
    }
}

bool tpm2_alg_util_is_sm4_size_valid(UINT16 size_in_bytes) {

    switch (size_in_bytes) {
    case 16:
        return true;
    default:
        LOG_ERR("Invalid SM4 key size, got %u bytes, expected 16",
                size_in_bytes);
        return false;
    }
}

TPM2_ALG_ID tpm2_alg_util_get_name_alg(ESYS_CONTEXT *ectx, ESYS_TR handle) {

    TPM2B_NAME *name = NULL;
    TSS2_RC rc = Esys_TR_GetName(ectx, handle, &name);
    if (rc != TSS2_RC_SUCCESS) {
        return TPM2_ALG_ERROR;
    }

    if (name->size < 2) {
        Esys_Free(name);
        return TPM2_ALG_ERROR;
    }

    UINT16 *big_endian_alg = (UINT16 *)name->name;

    TPM2_ALG_ID name_alg = tpm2_util_ntoh_16(*big_endian_alg);
    Esys_Free(name);
    return name_alg;
}
