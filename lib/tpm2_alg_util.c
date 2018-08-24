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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_attr_util.h"
#include "tpm2_errata.h"
#include "tpm2_hash.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

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

typedef alg_iter_res (*alg_iter)(TPM2_ALG_ID id, const char *name, tpm2_alg_util_flags flags, void *userdata);

static void tpm2_alg_util_for_each_alg(alg_iter iterator, void *userdata) {

    static const alg_pair algs[] = {

        // Assymetric
        { .name = "rsa", .id = TPM2_ALG_RSA, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },
        { .name = "ecc", .id = TPM2_ALG_ECC, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },

        // Symmetric
        { .name = "aes", .id = TPM2_ALG_AES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "camellia", .id = TPM2_ALG_CAMELLIA, .flags = tpm2_alg_util_flags_symmetric },

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

        // Mask Generation Functions
        { .name = "mgf1", .id = TPM2_ALG_MGF1, .flags = tpm2_alg_util_flags_mgf },

        // Signature Schemes
        { .name = "rsassa", .id = TPM2_ALG_RSASSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "rsapss", .id = TPM2_ALG_RSAPSS, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdsa", .id = TPM2_ALG_ECDSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdaa", .id = TPM2_ALG_ECDAA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecschnorr", .id = TPM2_ALG_ECSCHNORR, .flags = tpm2_alg_util_flags_sig },

        // Assyemtric Encryption Scheme
        { .name = "oaep", .id = TPM2_ALG_OAEP, .flags = tpm2_alg_util_flags_enc_scheme },
        { .name = "rsaes", .id = TPM2_ALG_RSAES, .flags = tpm2_alg_util_flags_enc_scheme },
        { .name = "ecdh", .id = TPM2_ALG_ECDH, .flags = tpm2_alg_util_flags_enc_scheme },


        // XXX are these sigs?
        { .name = "sm2", .id = TPM2_ALG_SM2, .flags = tpm2_alg_util_flags_sig },
        { .name = "sm4", .id = TPM2_ALG_SM4, .flags = tpm2_alg_util_flags_sig },

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
        { .name = "null", .id = TPM2_ALG_NULL, .flags = tpm2_alg_util_flags_misc },
    };

    size_t i;
    for (i=0; i < ARRAY_LEN(algs); i++) {
        const alg_pair *alg = &algs[i];
        alg_iter_res result = iterator(alg->id, alg->name, alg->flags, userdata);
        if (result != go) {
            return;
        }
    }
}

static bool handle_aes_raw(const char *ext, TPMT_SYM_DEF_OBJECT *s) {

    s->algorithm = TPM2_ALG_AES;

    if (*ext == '\0') {
        ext = "256";
    }

    if (!strncmp(ext, "128", 3)) {
        s->keyBits.aes = 128;
    } else if (!strncmp(ext, "256", 3)) {
        s->keyBits.aes = 256;
    } else if (!strncmp(ext, "384", 3)) {
        s->keyBits.aes = 384;
    } else if (!strncmp(ext, "512", 3)) {
        s->keyBits.aes = 512;
    } else {
        return false;
    }

    ext += 3;

    if (*ext == '\0') {
        ext = "null";
    }

    s->mode.sym = tpm2_alg_util_strtoalg(ext,
            tpm2_alg_util_flags_mode
            |tpm2_alg_util_flags_misc);
    if (s->mode.sym == TPM2_ALG_ERROR) {
        return false;
    }

    return true;
}

static bool handle_scheme_alg(const char *ext, TPMS_ASYM_PARMS *s) {

    if (ext[0] == '\0') {
        ext = "sha256";
    }

    s->scheme.details.anySig.hashAlg = tpm2_alg_util_strtoalg(ext, tpm2_alg_util_flags_hash);
    if (s->scheme.details.anySig.hashAlg == TPM2_ALG_ERROR) {
        return false;
    }

    return true;
}

static bool handle_ecdaa_scheme_details(const char *ext, TPMS_ASYM_PARMS *s) {

    /* Was it just "ecdaa" and we should set some default. */
    if (ext[0] == '\0') {
        ext = "4-sha256";
    }

    /*
     * Work off of a buffer since we expect const behavior
     */
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", ext);

    char *split = strchr(buf, '-');
    if (!split) {
        LOG_ERR("Invalid ecdaa scheme, expected <num>-<hash-alg>, got: \"%s\"", ext);
        return false;
    }

    char *num = buf;
    split[0] = '\0';
    split++;
    char *halg = split;

    TPMS_SIG_SCHEME_ECDAA *e = &s->scheme.details.ecdaa;

    bool res = tpm2_util_string_to_uint16(num, &e->count);
    if (!res) {
        LOG_ERR("Invalid ecdaa count, expected <num>-<hash-alg>, got: \"%s\"", ext);
        return false;
    }

    e->hashAlg = tpm2_alg_util_strtoalg(halg, tpm2_alg_util_flags_hash);
    if (e->hashAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid ecdaa hashing algorithm, expected <num>-<hash-alg>, got: \"%s\"", ext);
        return false;
    }

    return true;
}

/*
 * Macro for redundant code collapse in handle_asym_scheme_common
 * You cannot change all the variables in this, as they are dependent
 * on names in that routine; this is for simplicity.
 */
#define do_scheme_halg_and_advance(advance, alg) \
    do { \
        s->scheme.scheme = alg; \
        scheme += advance; \
        do_scheme_hash_alg = true; \
    } while (0)

static bool handle_asym_scheme_common(const char *ext, TPM2B_PUBLIC *public) {

    // Get the scheme and symetric details
    TPMS_ASYM_PARMS *s = &public->publicArea.parameters.asymDetail;

    bool is_restricted = !!(public->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED);

    // Get the scheme
    const char *scheme;
    char tmp[32];
    char *next = strchr(ext, ':');
    if (next) {
        snprintf(tmp, sizeof(tmp), "%.*s", (int)(next - ext), ext);
        scheme = tmp;
    } else {
        scheme = ext;
    }

    const char *orig = scheme;

    /*
     * This can fail... if the spec is missing scheme, default the scheme to NULL
     */
    bool is_missing_scheme = false;
    bool do_scheme_hash_alg = false;
    if (!strncmp(scheme, "oaep", 4)) {
        do_scheme_halg_and_advance(4, TPM2_ALG_OAEP);
    } else if (!strncmp(scheme, "ecdsa", 5)) {
        do_scheme_halg_and_advance(5, TPM2_ALG_ECDSA);
    } else if (!strncmp(scheme, "ecdh", 4)) {
        do_scheme_halg_and_advance(4, TPM2_ALG_ECDH);
    } else if (!strncmp(scheme, "ecschnorr", 9)) {
        do_scheme_halg_and_advance(9, TPM2_ALG_ECSCHNORR);
    } else if (!strncmp(scheme, "ecdaa", 5)) {
        /*
         * ECDAA has both a count and hashing algorithm
         */
        scheme += 5;
        s->scheme.scheme = TPM2_ALG_ECDAA;
        bool result = handle_ecdaa_scheme_details(scheme, s);
        if (!result) {
            /* don't print another error message */
            return false;
        }
    } else if (!strcmp(scheme, "rsaes")) {
        /*
         * rsaes has no hash alg or details, so it MUST
         * match exactly, notice strcmp and NOT strNcmp!
         */
        s->scheme.scheme = TPM2_ALG_RSAES;
    } else if (!strcmp("null", scheme)) {
        s->scheme.scheme = TPM2_ALG_NULL;
    } else {
        s->scheme.scheme = TPM2_ALG_NULL;
        is_missing_scheme = true;
    }

    if (do_scheme_hash_alg) {
        bool result = handle_scheme_alg(scheme, s);
        if (!result) {
            goto error;
        }
    }

    /*
     * If the scheme is set, both the encrypt and decrypt attributes cannot be set,
     * check to see if this is the case, and turn down:
     *  - DECRYPT - If its a signing scheme.
     *  - ENCRYPT - If its an asymmetric enc scheme.
     */
    if (s->scheme.scheme != TPM2_ALG_NULL) {
        bool is_both_set =
                !!(public->publicArea.objectAttributes & (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT));
        if (is_both_set) {
            tpm2_alg_util_flags flags = tpm2_alg_util_algtoflags(s->scheme.scheme);
            TPMA_OBJECT turn_down_flags = (flags & tpm2_alg_util_flags_sig) ?
                    TPMA_OBJECT_DECRYPT : TPMA_OBJECT_SIGN_ENCRYPT;
            public->publicArea.objectAttributes &= ~turn_down_flags;
        }
    }

    if (is_missing_scheme) {
        ext = scheme;
    } else {
        if (!next || *(next + 1) == '\0') {
            next = is_restricted ? ":aes128cfb" : ":null";
        }

        // Go past next :
        ext = ++next;
    }

    if (!strncmp(ext, "aes", 3)) {
        return handle_aes_raw(&ext[3], &s->symmetric);
    } else if (!strcmp(ext, "null")) {
        s->symmetric.algorithm = TPM2_ALG_NULL;
        return true;
    }

error:
    LOG_ERR("Unsupported scheme, got: \"%s\"", orig);
    return false;
}

static bool handle_rsa(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_RSA;
    TPMS_RSA_PARMS *r = &public->publicArea.parameters.rsaDetail;
    r->exponent = 0;

    /*
     * Deal with normalizing the input strings.
     *
     * "rsa --> maps to rsa2048:aes128cbc
     * "rsa:aes --> maps to rsa2048:aes128cbc
     * "rsa:null" -- maps to rsa2048:null
     *
     * This function is invoked with rsa removed.
     */

    bool is_restricted = !!(public->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED);

    size_t len = strlen(ext);
    if (len == 0 || ext[0] == ':') {
        ext = "2048";
    }

    // Deal with bit size
    if (!strncmp(ext, "1024", 4)) {
        r->keyBits = 1024;
    } else if (!strncmp(ext, "2048", 4)) {
        r->keyBits = 2048;
    } else if (!strncmp(ext, "4096", 4)) {
        r->keyBits = 4096;
    } else {
        return false;
    }

    // go past bit size
    ext += 4;

    if (*ext != ':' || *ext + 1 == '\0') {
        ext = is_restricted ? ":null:aes128cfb" : ":null:null";
    }

    // go past the colon separator
    ext++;

    // Get the scheme and symetric details
    return handle_asym_scheme_common(ext, public);
}

static bool handle_ecc(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_ECC;

    bool is_restricted = !!(public->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED);

    size_t len = strlen(ext);
    if (len == 0 || ext[0] == ':') {
        ext = "256";
    }

    TPMS_ECC_PARMS *e = &public->publicArea.parameters.eccDetail;
    e->kdf.scheme = TPM2_ALG_NULL;

    if (!strncmp(ext, "192", 3)) {
        e->curveID = TPM2_ECC_NIST_P192;
    } else if (!strncmp(ext, "224", 3)) {
        e->curveID = TPM2_ECC_NIST_P224;
    } else if (!strncmp(ext, "256", 3)) {
        e->curveID = TPM2_ECC_NIST_P256;
    } else if (!strncmp(ext, "384", 3)) {
        e->curveID = TPM2_ECC_NIST_P384;
    } else if (!strncmp(ext, "521", 3)) {
        e->curveID = TPM2_ECC_NIST_P521;
    } else {
        return false;
    }

    // go past ecc size
    ext += 3;

    if (*ext != ':' || *ext + 1 == '\0') {
        ext = is_restricted ? ":null:aes128cfb" : ":null:null";
    }

    // go past the colon separator
    ext++;

    return handle_asym_scheme_common(ext, public);
}

static bool handle_aes(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_SYMCIPHER;

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &public->publicArea.objectAttributes);

    TPMT_SYM_DEF_OBJECT *s = &public->publicArea.parameters.symDetail.sym;
    return handle_aes_raw(ext, s);
}

static bool handle_xor(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_KEYEDHASH;

    /*
     * Fixup and normalize things like:
     * xor --> xor:sha256
     */

    if (*ext == '\0') {
        ext = ":sha256";
    }

    // Move past first colon separator from xor to hash
    ext++;

    TPMT_KEYEDHASH_SCHEME *s = &public->publicArea.parameters.keyedHashDetail.scheme;
    s->scheme = TPM2_ALG_XOR;
    s->details.exclusiveOr.kdf = TPM2_ALG_KDF1_SP800_108;

    TPM2_ALG_ID alg = tpm2_alg_util_strtoalg(ext, tpm2_alg_util_flags_hash);
    if (alg == TPM2_ALG_ERROR) {
        LOG_ERR("Spec does not contain hash algorithm");
        return false;
    }
    s->details.exclusiveOr.hashAlg = alg;

    return true;
}

static bool handle_hmac(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_KEYEDHASH;
    public->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;

    /*
     * Fixup and normalize things like:
     * hmac --> hmac:sha256
     *
     * Note this is called with hmac stripped
     */

    if (*ext == ':') {
        ext++;
    }

    if (*ext == '\0') {
        ext = "sha256";
    }

    TPM2_ALG_ID alg = tpm2_alg_util_strtoalg(ext, tpm2_alg_util_flags_hash);
    if (alg == TPM2_ALG_ERROR) {
        return false;
    }

    public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = alg;
    return true;
}

static bool handle_keyedhash(TPM2B_PUBLIC *public) {

        public->publicArea.type = TPM2_ALG_KEYEDHASH;
        public->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
        return true;
}

static const char *alg_spec_fixup(const char *alg_spec) {

    /*
     * symcipher used to imply aes128cfb.
     */
    if (!strcmp(alg_spec, "symcipher")) {
        return "aes128cfb";
    }

    return alg_spec;
}

static bool tpm2_alg_util_handle_ext_alg(const char *alg_spec, TPM2B_PUBLIC *public) {

    /*
     * Fix up numerics, like 0x1 for rsa
     */
    TPM2_ALG_ID alg;
    bool res = tpm2_util_string_to_uint16(alg_spec, &alg);
    if (res) {
        alg_spec = tpm2_alg_util_algtostr(alg,
                tpm2_alg_util_flags_base);
        if (!alg_spec) {
            return false;
        }
        alg_spec = alg_spec_fixup(alg_spec);
    }

    /*
     * TODO handle Camelia
     */
    res = false;
    if (!strncmp(alg_spec, "rsa", 3)) {
        res = handle_rsa(&alg_spec[3], public);
    } else if (!strncmp(alg_spec, "aes", 3)) {
        res = handle_aes(&alg_spec[3], public);
    } else if (!strncmp(alg_spec, "xor", 3)) {
        res = handle_xor(&alg_spec[3], public);
    } else if (!strncmp(alg_spec, "ecc", 3)) {
        res = handle_ecc(&alg_spec[3], public);
    } else if (!strncmp(alg_spec, "hmac", 4)) {
        res = handle_hmac(&alg_spec[4], public);
    } else if (!strcmp(alg_spec, "keyedhash")) {
        res = handle_keyedhash(public);
    }

    if (!res) {
        LOG_ERR("Could not handle algorithm spec: \"%s\"", alg_spec);
    }

    return res;
}

static alg_iter_res find_match(TPM2_ALG_ID id, const char *name, tpm2_alg_util_flags flags, void *userdata) {

    alg_pair *search_data = (alg_pair *)userdata;

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
        return  res;
    }

    return go;
}

TPM2_ALG_ID tpm2_alg_util_strtoalg(const char *name, tpm2_alg_util_flags flags) {

    alg_pair userdata = {
        .name = name,
        .id = TPM2_ALG_ERROR,
        .flags = flags
    };

    if (name) {
        tpm2_alg_util_for_each_alg(find_match, &userdata);
    }

    return userdata.id;
}

const char *tpm2_alg_util_algtostr(TPM2_ALG_ID id, tpm2_alg_util_flags flags) {

    alg_pair userdata = {
        .name = NULL,
        .id = id,
        .flags = flags
    };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata.name;
}

tpm2_alg_util_flags tpm2_alg_util_algtoflags(TPM2_ALG_ID id) {

    alg_pair userdata = {
        .name = NULL,
        .id = id,
        .flags = tpm2_alg_util_flags_any,
        ._flags = tpm2_alg_util_flags_none
    };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata._flags;
}


TPM2_ALG_ID tpm2_alg_util_from_optarg(const char *optarg, tpm2_alg_util_flags flags) {

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
    case TPM2_ALG_SHA1 :
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256 :
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384 :
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512 :
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256 :
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
            LOG_ERR("Expecting : in digest spec, not found, got: \"%s\"", spec_str);
            return false;
        }

        *digest_spec_str = '\0';
        digest_spec_str++;

        bool result = tpm2_util_string_to_uint32(pcr_index_str, &dspec->pcr_index);
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
            TPM2_ALG_ID alg = tpm2_alg_util_from_optarg(stralg, tpm2_alg_util_flags_hash);
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

            UINT16 size =  expected_hash_size;
            int rc = tpm2_util_hex_to_byte_structure(data, &size,
                    digest_data);
            if (rc) {
                LOG_ERR("Error \"%s\" converting hex string as data, got:"
                    " \"%s\"", hex_to_byte_err(rc), data);
                return false;
            }

            if (expected_hash_size != size) {
                LOG_ERR(
                        "Algorithm \"%s\" expects a size of %u bytes, got: %u",
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

static bool get_key_type(ESYS_CONTEXT *ectx, TPMI_DH_OBJECT objectHandle,
        TPMI_ALG_PUBLIC *type) {

    TPM2B_PUBLIC *out_public;

    TSS2_RC rval = Esys_ReadPublic(ectx, objectHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &out_public, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ReadPublic, rval);
        return false;
    }

    *type = out_public->publicArea.type;

    free(out_public);

    return true;
}

bool get_signature_scheme(ESYS_CONTEXT *context,
        ESYS_TR keyHandle, TPMI_ALG_HASH halg,
        TPMT_SIG_SCHEME *scheme) {

    TPM2_ALG_ID type;
    bool result = get_key_type(context, keyHandle, &type);
    if (!result) {
        return false;
    }

    switch (type) {
    case TPM2_ALG_RSA :
        scheme->scheme = TPM2_ALG_RSASSA;
        scheme->details.rsassa.hashAlg = halg;
        break;
    case TPM2_ALG_KEYEDHASH :
        scheme->scheme = TPM2_ALG_HMAC;
        scheme->details.hmac.hashAlg = halg;
        break;
    case TPM2_ALG_ECC :
        scheme->scheme = TPM2_ALG_ECDSA;
        scheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM2_ALG_SYMCIPHER :
    default:
        LOG_ERR("Unknown key type, got: 0x%x", type);
        return false;
    }

    return true;
}

bool tpm2_alg_util_public_init(char *alg_details, char *name_halg, char *attrs, char *auth_policy, TPMA_OBJECT def_attrs,
        TPM2B_PUBLIC *public) {

    memset(public, 0, sizeof(*public));

    /* load a policy from a path if present */
    if (auth_policy) {
        public->publicArea.authPolicy.size = sizeof(public->publicArea.authPolicy.buffer);
        bool res = files_load_bytes_from_path(auth_policy,
                    public->publicArea.authPolicy.buffer, &public->publicArea.authPolicy.size);
        if (!res) {
            return false;
        }
    }

    /* Set the hashing algorithm used for object name */
    public->publicArea.nameAlg =
            name_halg ? tpm2_alg_util_from_optarg(name_halg, tpm2_alg_util_flags_hash) : TPM2_ALG_SHA256;
    if (public->publicArea.nameAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid name hashing algorithm, got\"%s\"", name_halg);
        return false;
    }

    /* Set specified attributes or use default */
    if (attrs) {
        bool res = tpm2_attr_util_obj_from_optarg(attrs,
                &public->publicArea.objectAttributes);
        if (!res) {
            return res;
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
        return false;
    }

    if (attrs && tmp.publicArea.objectAttributes != public->publicArea.objectAttributes) {

        char *proposed_attrs = tpm2_attr_util_obj_attrtostr(tmp.publicArea.objectAttributes);
        LOG_ERR("Specified attributes \"%s\" and algorithm specifier \"%s\" do not work together, try"
                "attributes: \"%s\"", attrs, alg_details, proposed_attrs);
        free(proposed_attrs);
        return false;
    }

    *public = tmp;

    return true;
}

const char *tpm2_alg_util_ecc_to_str(TPM2_ECC_CURVE curve_id) {

    switch(curve_id) {
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

