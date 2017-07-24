//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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
//**********************************************************************;
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>

#include <cmocka.h>
#include <sapi/tpm20.h>

#include "tpm2_util.h"
#include "tpm2_alg_util.h"

#define xstr(s) str(s)
#define str(s) #s

#define single_item_test_get(friendly) \
    cmocka_unit_test(test_tpm2_alg_util_convert_##friendly)

#define single_item_test(friendly, value) \
    static void test_tpm2_alg_util_convert_##friendly(void **state) { \
    \
        (void)state; \
    \
        TPM_ALG_ID found_id = tpm2_alg_util_strtoalg(str(friendly)); \
        const char *found_str = tpm2_alg_util_algtostr(value); \
        TPM_ALG_ID from_hex_str = tpm2_alg_util_from_optarg(xstr(value));    \
        TPM_ALG_ID from_nice_str = tpm2_alg_util_from_optarg(str(friendly));    \
        \
        assert_ptr_not_equal(found_id, NULL); \
        assert_string_equal(str(friendly), found_str); \
        assert_int_equal(value, found_id); \
        assert_int_equal(value, from_hex_str); \
        assert_int_equal(value, from_nice_str); \
    }

single_item_test(rsa, ALG_RSA_VALUE)
/*
 * sha sha1 is it's own test, as alg to string
 * can return either, based on the map ordering.
 *
 */
single_item_test(hmac, ALG_HMAC_VALUE)
single_item_test(aes, ALG_AES_VALUE)
single_item_test(mgf1, ALG_MGF1_VALUE)
single_item_test(keyedhash, ALG_KEYEDHASH_VALUE)
single_item_test(xor, ALG_XOR_VALUE)
single_item_test(sha256, ALG_SHA256_VALUE)
single_item_test(sha384, ALG_SHA384_VALUE)
single_item_test(sha512, ALG_SHA512_VALUE)
single_item_test(null, ALG_NULL_VALUE)
single_item_test(sm3_256, ALG_SM3_256_VALUE)
single_item_test(sm4, ALG_SM4_VALUE)
single_item_test(rsassa, ALG_RSASSA_VALUE)
single_item_test(rsaes, ALG_RSAES_VALUE)
single_item_test(rsapss, ALG_RSAPSS_VALUE)
single_item_test(oaep, ALG_OAEP_VALUE)
single_item_test(ecdsa, ALG_ECDSA_VALUE)
single_item_test(ecdh, ALG_ECDH_VALUE)
single_item_test(ecdaa, ALG_ECDAA_VALUE)
single_item_test(sm2, ALG_SM2_VALUE)
single_item_test(ecschnorr, ALG_ECSCHNORR_VALUE)
single_item_test(ecmqv, ALG_ECMQV_VALUE)
single_item_test(kdf1_sp800_56a, ALG_KDF1_SP800_56A_VALUE)
single_item_test(kdf2, ALG_KDF2_VALUE)
single_item_test(kdf1_sp800_108, ALG_KDF1_SP800_108_VALUE)
single_item_test(ecc, ALG_ECC_VALUE)
single_item_test(symcipher, ALG_SYMCIPHER_VALUE)
single_item_test(camellia, ALG_CAMELLIA_VALUE)
single_item_test(sha3_256, ALG_SHA3_256_VALUE)
single_item_test(sha3_384, ALG_SHA3_384_VALUE)
single_item_test(sha3_512, ALG_SHA3_512_VALUE)
single_item_test(ctr, ALG_CTR_VALUE)
single_item_test(ofb, ALG_OFB_VALUE)
single_item_test(cbc, ALG_CBC_VALUE)
single_item_test(cfb, ALG_CFB_VALUE)
single_item_test(ecb, ALG_ECB_VALUE)

typedef struct find_unk_data find_unk_data;
struct find_unk_data {
    TPM_ALG_ID *ids;
    size_t len;
};

static bool find_unkown(TPM_ALG_ID id, const char *name, void *userdata) {

    (void) name;

    find_unk_data *d = (find_unk_data *) userdata;

    size_t i = 0;
    for (i = 0; i < d->len; i++) {
        if (d->ids[i] == id) {
            d->ids[i] = TPM_ALG_ERROR;
        }
    }

    return false;
}

static void test_tpm2_alg_util_sha_test(void **state) {

    (void) state;

    TPM_ALG_ID sha_found_id = tpm2_alg_util_strtoalg("sha");
    const char *sha_found_str = tpm2_alg_util_algtostr(ALG_SHA_VALUE);

    TPM_ALG_ID sha1_found_id = tpm2_alg_util_strtoalg("sha1");
    const char *sha1_found_str = tpm2_alg_util_algtostr(ALG_SHA1_VALUE);

    TPM_ALG_ID sha_from_hex_str = tpm2_alg_util_from_optarg("sha");
    TPM_ALG_ID sha_from_nice_str = tpm2_alg_util_from_optarg(xstr(ALG_SHA_VALUE));

    TPM_ALG_ID sha1_from_hex_str = tpm2_alg_util_from_optarg("sha1");
    TPM_ALG_ID sha1_from_nice_str = tpm2_alg_util_from_optarg(xstr(ALG_SHA1_VALUE));

    assert_int_equal(ALG_SHA_VALUE, sha_found_id);
    assert_int_equal(ALG_SHA_VALUE, sha_from_hex_str);
    assert_int_equal(ALG_SHA_VALUE, sha_from_nice_str);

    assert_int_equal(ALG_SHA1_VALUE, sha1_found_id);
    assert_int_equal(ALG_SHA_VALUE, sha1_from_hex_str);
    assert_int_equal(ALG_SHA_VALUE, sha1_from_nice_str);

    bool sha_pass = false;
    sha_pass = !strcmp(sha_found_str, "sha");
    sha_pass = !strcmp(sha_found_str, "sha1") || sha_pass;

    assert_true(sha_pass);

    bool sha1_pass = false;
    sha1_pass = !strcmp(sha1_found_str, "sha");
    sha1_pass = !strcmp(sha1_found_str, "sha") || sha1_pass;

    assert_true(sha1_pass);
}

/* make sure no one adds an algorithm to the map that isn't tested */
static void test_tpm2_alg_util_everything_is_tested(void **state) {

    (void) state;

    TPM_ALG_ID known_algs[] = {
    ALG_RSA_VALUE,
    ALG_SHA_VALUE,
    ALG_SHA1_VALUE,
    ALG_HMAC_VALUE,
    ALG_AES_VALUE,
    ALG_MGF1_VALUE,
    ALG_KEYEDHASH_VALUE,
    ALG_XOR_VALUE,
    ALG_SHA256_VALUE,
    ALG_SHA384_VALUE,
    ALG_SHA512_VALUE,
    ALG_NULL_VALUE,
    ALG_SM3_256_VALUE,
    ALG_SM4_VALUE,
    ALG_RSASSA_VALUE,
    ALG_RSAES_VALUE,
    ALG_RSAPSS_VALUE,
    ALG_OAEP_VALUE,
    ALG_ECDSA_VALUE,
    ALG_ECDH_VALUE,
    ALG_ECDAA_VALUE,
    ALG_SM2_VALUE,
    ALG_ECSCHNORR_VALUE,
    ALG_ECMQV_VALUE,
    ALG_KDF1_SP800_56A_VALUE,
    ALG_KDF2_VALUE,
    ALG_KDF1_SP800_108_VALUE,
    ALG_ECC_VALUE,
    ALG_SYMCIPHER_VALUE,
    ALG_CAMELLIA_VALUE,
    ALG_SHA3_256_VALUE,
    ALG_SHA3_384_VALUE,
    ALG_SHA3_512_VALUE,
    ALG_CTR_VALUE,
    ALG_OFB_VALUE,
    ALG_CBC_VALUE,
    ALG_CFB_VALUE,
    ALG_ECB_VALUE };

    find_unk_data userdata = {
        .ids = known_algs,
        .len = ARRAY_LEN(known_algs)
    };

    /*
     * Go through each element in the list, and check it against
     * the known algorithm list, if it's present, set the element
     * in the known list to TPM_ALG_ERROR. At the end, the list
     * should only contain TPM_ALG_ERROR entries. Anything else
     * indicates that the map of known algorithms was added to,
     * but a test was not added.
     *
     * Tests that are removed will fail the single_item tests
     * above since there will not be a match.
     */
    tpm2_alg_util_for_each_alg(find_unkown, &userdata);

    size_t i;
    for (i = 0; i < ARRAY_LEN(known_algs); i++) {
        assert_int_equal(known_algs[i], TPM_ALG_ERROR);
    }
}

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        single_item_test_get(rsa),
        cmocka_unit_test(test_tpm2_alg_util_sha_test),
        single_item_test_get(hmac),
        single_item_test_get(aes),
        single_item_test_get(mgf1),
        single_item_test_get(keyedhash),
        single_item_test_get(xor),
        single_item_test_get(sha256),
        single_item_test_get(sha384),
        single_item_test_get(sha512),
        single_item_test_get(null),
        single_item_test_get(sm3_256),
        single_item_test_get(sm4),
        single_item_test_get(rsassa),
        single_item_test_get(rsaes),
        single_item_test_get(rsapss),
        single_item_test_get(oaep),
        single_item_test_get(ecdsa),
        single_item_test_get(ecdh),
        single_item_test_get(ecdaa),
        single_item_test_get(sm2),
        single_item_test_get(ecschnorr),
        single_item_test_get(ecmqv),
        single_item_test_get(kdf1_sp800_56a),
        single_item_test_get(kdf2),
        single_item_test_get(kdf1_sp800_108),
        single_item_test_get(ecc),
        single_item_test_get(symcipher),
        single_item_test_get(camellia),
        single_item_test_get(sha3_256),
        single_item_test_get(sha3_384),
        single_item_test_get(sha3_512),
        single_item_test_get(ctr),
        single_item_test_get(ofb),
        single_item_test_get(cbc),
        single_item_test_get(cfb),
        single_item_test_get(ecb),
        cmocka_unit_test(test_tpm2_alg_util_everything_is_tested)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
