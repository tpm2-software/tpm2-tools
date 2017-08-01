#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm_hash.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

typedef struct alg_pair alg_pair;
struct alg_pair {
    const char *name;
    TPM_ALG_ID id;
};

void tpm2_alg_util_for_each_alg(tpm2_alg_util_alg_iteraror iterator, void *userdata) {

    static const alg_pair algs[] = {
        { .name = "rsa", .id = ALG_RSA_VALUE },
        { .name = "sha", .id = ALG_SHA_VALUE },
        { .name = "sha1", .id = ALG_SHA1_VALUE },
        { .name = "hmac", .id = ALG_HMAC_VALUE },
        { .name = "aes", .id = ALG_AES_VALUE },
        { .name = "mgf1", .id = ALG_MGF1_VALUE },
        { .name = "keyedhash", .id = ALG_KEYEDHASH_VALUE },
        { .name = "xor", .id = ALG_XOR_VALUE },
        { .name = "sha256", .id = ALG_SHA256_VALUE },
        { .name = "sha384", .id = ALG_SHA384_VALUE },
        { .name = "sha512", .id = ALG_SHA512_VALUE },
        { .name = "null", .id = ALG_NULL_VALUE },
        { .name = "sm3_256", .id = ALG_SM3_256_VALUE },
        { .name = "sm4", .id = ALG_SM4_VALUE },
        { .name = "rsassa", .id = ALG_RSASSA_VALUE },
        { .name = "rsaes", .id = ALG_RSAES_VALUE },
        { .name = "rsapss", .id = ALG_RSAPSS_VALUE },
        { .name = "oaep", .id = ALG_OAEP_VALUE },
        { .name = "ecdsa", .id = ALG_ECDSA_VALUE },
        { .name = "ecdh", .id = ALG_ECDH_VALUE },
        { .name = "ecdaa", .id = ALG_ECDAA_VALUE },
        { .name = "sm2", .id = ALG_SM2_VALUE },
        { .name = "ecschnorr", .id = ALG_ECSCHNORR_VALUE },
        { .name = "ecmqv", .id = ALG_ECMQV_VALUE },
        { .name = "kdf1_sp800_56a", .id = ALG_KDF1_SP800_56A_VALUE },
        { .name = "kdf2", .id = ALG_KDF2_VALUE },
        { .name = "kdf1_sp800_108", .id = ALG_KDF1_SP800_108_VALUE },
        { .name = "ecc", .id = ALG_ECC_VALUE },
        { .name = "symcipher", .id = ALG_SYMCIPHER_VALUE },
        { .name = "camellia", .id = ALG_CAMELLIA_VALUE },
        { .name = "sha3_256", .id = ALG_SHA3_256_VALUE },
        { .name = "sha3_384", .id = ALG_SHA3_384_VALUE },
        { .name = "sha3_512", .id = ALG_SHA3_512_VALUE },
        { .name = "ctr", .id = ALG_CTR_VALUE },
        { .name = "ofb", .id = ALG_OFB_VALUE },
        { .name = "cbc", .id = ALG_CBC_VALUE },
        { .name = "cfb", .id = ALG_CFB_VALUE },
        { .name = "ecb", .id = ALG_ECB_VALUE },
    };

    size_t i;
    for (i=0; i < ARRAY_LEN(algs); i++) {
        const alg_pair *alg = &algs[i];
        bool result = iterator(alg->id, alg->name, userdata);
        if (result) {
            return;
        }
    }
}

static bool find_match(TPM_ALG_ID id, const char *name, void *userdata) {

    alg_pair *search_data = (alg_pair *)userdata;

    /*
     * if name, then search on name, else
     * search by id.
     */
    if (search_data->name && !strcmp(search_data->name, name)) {
        search_data->id = id;
        return true;
    } else if (search_data->id == id) {
        search_data->name = name;
        return true;
    }

    return false;
}

TPM_ALG_ID tpm2_alg_util_strtoalg(const char *name) {

    alg_pair userdata = {
        .name = name,
        .id = TPM_ALG_ERROR
    };

    if (name) {
        tpm2_alg_util_for_each_alg(find_match, &userdata);
    }

    return userdata.id;
}

const char *tpm2_alg_util_algtostr(TPM_ALG_ID id) {

    alg_pair userdata = {
        .name = NULL,
        .id = id
    };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata.name;
}

TPM_ALG_ID tpm2_alg_util_from_optarg(char *optarg) {

    TPM_ALG_ID halg;
    bool res = tpm2_util_string_to_uint16(optarg, &halg);
    if (!res) {
        halg = tpm2_alg_util_strtoalg(optarg);
    }
    return halg;
}

bool tpm2_alg_util_is_hash_alg(TPM_ALG_ID id) {

    switch (id) {
    case TPM_ALG_SHA1 :
        /* fallsthrough */
    case TPM_ALG_SHA256 :
        /* fallsthrough */
    case TPM_ALG_SHA384 :
        /* fallsthrough */
    case TPM_ALG_SHA512 :
        /* fallsthrough */
    case TPM_ALG_SM3_256 :
        return true;
        /* no default */
    }

    return false;
}

static UINT16 hash_alg_size(TPMI_ALG_HASH id) {

    switch (id) {
    case TPM_ALG_SHA1 :
        return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256 :
        return SHA256_DIGEST_SIZE;
    case TPM_ALG_SHA384 :
        return SHA384_DIGEST_SIZE;
    case TPM_ALG_SHA512 :
        return SHA512_DIGEST_SIZE;
    case TPM_ALG_SM3_256 :
        return SM3_256_DIGEST_SIZE;
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
         * Split <pcr index>:<hash alg>=<hash value|filename>,... on : and separate with null byte, ie:
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
            TPM_ALG_ID alg = tpm2_alg_util_from_optarg(stralg);
            if (alg == TPM_ALG_ERROR) {
                LOG_ERR("Could not convert algorithm, got: \"%s\"", stralg);
                return false;
            }

            bool is_hash_alg = tpm2_alg_util_is_hash_alg(alg);
            if (!is_hash_alg) {
                LOG_ERR("Algorithm is not a hash algorithm, got: \"%s\"",
                        stralg);
                return false;
            }

            d->hashAlg = alg;

            /* fill up the TPMT_HA structure with algorithm and digest */
            BYTE *digest_data = (BYTE *) &d->digest;

            UINT16 expected_hash_size = hash_alg_size(alg);
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
