#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

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
