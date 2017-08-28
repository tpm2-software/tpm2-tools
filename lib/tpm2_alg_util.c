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
        { .name = "rsa", .id = TPM_ALG_RSA },
        { .name = "sha", .id = TPM_ALG_SHA },
        { .name = "sha1", .id = TPM_ALG_SHA1 },
        { .name = "hmac", .id = TPM_ALG_HMAC },
        { .name = "aes", .id = TPM_ALG_AES },
        { .name = "mgf1", .id = TPM_ALG_MGF1 },
        { .name = "keyedhash", .id = TPM_ALG_KEYEDHASH },
        { .name = "xor", .id = TPM_ALG_XOR },
        { .name = "sha256", .id = TPM_ALG_SHA256 },
        { .name = "sha384", .id = TPM_ALG_SHA384 },
        { .name = "sha512", .id = TPM_ALG_SHA512 },
        { .name = "null", .id = TPM_ALG_NULL },
        { .name = "sm3_256", .id = TPM_ALG_SM3_256 },
        { .name = "sm4", .id = TPM_ALG_SM4 },
        { .name = "rsassa", .id = TPM_ALG_RSASSA },
        { .name = "rsaes", .id = TPM_ALG_RSAES },
        { .name = "rsapss", .id = TPM_ALG_RSAPSS },
        { .name = "oaep", .id = TPM_ALG_OAEP },
        { .name = "ecdsa", .id = TPM_ALG_ECDSA },
        { .name = "ecdh", .id = TPM_ALG_ECDH },
        { .name = "ecdaa", .id = TPM_ALG_ECDAA },
        { .name = "sm2", .id = TPM_ALG_SM2 },
        { .name = "ecschnorr", .id = TPM_ALG_ECSCHNORR },
        { .name = "ecmqv", .id = TPM_ALG_ECMQV },
        { .name = "kdf1_sp800_56a", .id = TPM_ALG_KDF1_SP800_56A },
        { .name = "kdf2", .id = TPM_ALG_KDF2 },
        { .name = "kdf1_sp800_108", .id = TPM_ALG_KDF1_SP800_108 },
        { .name = "ecc", .id = TPM_ALG_ECC },
        { .name = "symcipher", .id = TPM_ALG_SYMCIPHER },
        { .name = "camellia", .id = TPM_ALG_CAMELLIA },
        { .name = "sha3_256", .id = TPM_ALG_SHA3_256 },
        { .name = "sha3_384", .id = TPM_ALG_SHA3_384 },
        { .name = "sha3_512", .id = TPM_ALG_SHA3_512 },
        { .name = "ctr", .id = TPM_ALG_CTR },
        { .name = "ofb", .id = TPM_ALG_OFB },
        { .name = "cbc", .id = TPM_ALG_CBC },
        { .name = "cfb", .id = TPM_ALG_CFB },
        { .name = "ecb", .id = TPM_ALG_ECB },
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

UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id) {

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
    case TPM_ALG_RSASSA:
        *size = sizeof((*signature).signature.rsassa.sig.t.buffer);
        buffer = malloc(*size);
        if(! buffer) {
            goto nomem;
        }
        memcpy(buffer, (*signature).signature.rsassa.sig.t.buffer, *size);
        break;
    case TPM_ALG_HMAC: {
        TPMU_HA *hmac_sig = &((*signature).signature.hmac.digest);
        *size = tpm2_alg_util_get_hash_size((*signature).signature.hmac.hashAlg);
        buffer = malloc(*size);
        if(! buffer) {
            goto nomem;
        }
        memcpy(buffer, &(hmac_sig->na), *size);
        break;
    }
    case TPM_ALG_ECDSA: {
        const size_t ECC_PAR_LEN = sizeof(TPM2B_ECC_PARAMETER);
        *size = ECC_PAR_LEN * 2;
        buffer = malloc(*size);
        if(! buffer) {
            goto nomem;
        }
        memcpy(buffer,
            (UINT8*)&((*signature).signature.ecdsa.signatureR),
            ECC_PAR_LEN
        );
        memcpy(buffer + ECC_PAR_LEN,
            (UINT8*)&((*signature).signature.ecdsa.signatureS),
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
