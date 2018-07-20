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

#include <tss2/tss2_sys.h>

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
        { .name = "ecdh", .id = TPM2_ALG_ECDH, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdaa", .id = TPM2_ALG_ECDAA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecschnorr", .id = TPM2_ALG_ECSCHNORR, .flags = tpm2_alg_util_flags_sig },

        // Assyemtric Encryption Scheme
        { .name = "oaep", .id = TPM2_ALG_OAEP, .flags = tpm2_alg_util_flags_enc_scheme },
        { .name = "rsaes", .id = TPM2_ALG_RSAES, .flags = tpm2_alg_util_flags_enc_scheme },


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

static bool handle_rsa(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_RSA;
    TPMS_RSA_PARMS *r = &public->publicArea.parameters.rsaDetail;
    r->exponent = 0;

    /*
     * Deal with normalizing the input strings.
     *
     * "rsa --> maps to rsa2048:aes256cbc
     * "rsa:aes --> maps to rsa2048:aes256cbc
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
        ext = is_restricted ? ":null:aes256cfb" : ":null:null";
    }

    // go past the colon separator
    ext++;

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

    /*
     * This can fail... if the spec is missing scheme, default the scheme to NULL
     */
    bool is_missing_scheme = false;
    r->scheme.scheme = tpm2_alg_util_strtoalg(scheme,
            tpm2_alg_util_flags_enc_scheme
            |tpm2_alg_util_flags_misc);
    if (r->scheme.scheme == TPM2_ALG_ERROR) {
        r->scheme.scheme = TPM2_ALG_NULL;
        is_missing_scheme = true;
    }

    if (is_restricted && r->scheme.scheme != TPM2_ALG_NULL) {
        LOG_ERR("Restricted objects require a NULL scheme");
        return false;
    }

    if (is_missing_scheme) {
        ext = scheme;
    } else {
        if (!next || *(next + 1) == '\0') {
            next = is_restricted ? ":aes256cfb" : ":null";
        }

        // Go past next :
        ext = ++next;
    }

    if (!strncmp(ext, "aes", 3)) {
        return handle_aes_raw(&ext[3], &r->symmetric);
    } else if (!strcmp(ext, "null")) {
        r->symmetric.algorithm = TPM2_ALG_NULL;
        return true;
    }

    return false;
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
        ext = is_restricted ? ":null:aes256cfb" : ":null:null";
    }

    // go past the colon separator
    ext++;

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

    e->scheme.scheme = tpm2_alg_util_strtoalg(scheme,
            tpm2_alg_util_flags_enc_scheme
            |tpm2_alg_util_flags_misc);
    if (e->scheme.scheme == TPM2_ALG_ERROR) {
        return false;
    }

    if (is_restricted && e->scheme.scheme != TPM2_ALG_NULL) {
        LOG_ERR("Restricted objects require a NULL scheme");
        return false;
    }

    if (!next || *(next + 1) == '\0') {
        next = is_restricted ? ":aes256cfb" : ":null";
    }

    // Go past next :
    ext = ++next;

    if (!strncmp(ext, "aes", 3)) {
        return handle_aes_raw(&ext[3], &e->symmetric);
    } else if (!strcmp(ext, "null")) {
        e->symmetric.algorithm = TPM2_ALG_NULL;
        return true;
    }

    return false;
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

UINT8* tpm2_extract_plain_signature(UINT16 *size, TPMT_SIGNATURE *signature) {

    UINT8 *buffer = NULL;
    *size = 0;

    switch (signature->sigAlg) {
    case TPM2_ALG_RSASSA:
        *size = sizeof(signature->signature.rsassa.sig.buffer);
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsassa.sig.buffer, *size);
        break;
    case TPM2_ALG_HMAC: {
        TPMU_HA *hmac_sig = &(signature->signature.hmac.digest);
        *size = tpm2_alg_util_get_hash_size(signature->signature.hmac.hashAlg);
        if (*size == 0) {
            LOG_ERR("Hash algorithm %d has 0 size",
                signature->signature.hmac.hashAlg);
            goto nomem;
        }
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, hmac_sig, *size);
        break;
    }
    case TPM2_ALG_ECDSA: {
        const size_t ECC_PAR_LEN = sizeof(TPM2B_ECC_PARAMETER);
        *size = ECC_PAR_LEN * 2;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer,
            (UINT8*)&(signature->signature.ecdsa.signatureR),
            ECC_PAR_LEN
        );
        memcpy(buffer + ECC_PAR_LEN,
            (UINT8*)&(signature->signature.ecdsa.signatureS),
            ECC_PAR_LEN
        );
        break;
    }
    default:
        LOG_ERR("%s: unknown signature scheme: 0x%x", __func__,
            signature->sigAlg);
        return NULL;
    }

    return buffer;
nomem:
    LOG_ERR("%s: couldn't allocate memory", __func__);
    return NULL;
}

static bool get_key_type(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT objectHandle,
        TPMI_ALG_PUBLIC *type) {

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TSS2_RC rval = Tss2_Sys_ReadPublic(sapi_context, objectHandle, 0, &out_public, &name,
            &qualified_name, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Sys_ReadPublic failed, error code: 0x%x", rval);
        return false;
    }
    *type = out_public.publicArea.type;
    return true;
}

bool get_signature_scheme(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle, TPMI_ALG_HASH halg,
        TPMT_SIG_SCHEME *scheme) {

    TPM2_ALG_ID type;
    bool result = get_key_type(sapi_context, keyHandle, &type);
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

    return tpm2_alg_util_handle_ext_alg(alg_details, public);
}
