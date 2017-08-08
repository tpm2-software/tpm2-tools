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
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

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
        TPM_ALG_ID from_hex_str = tpm2_alg_util_from_optarg(str(value));    \
        TPM_ALG_ID from_nice_str = tpm2_alg_util_from_optarg(str(friendly));    \
        \
        assert_ptr_not_equal(found_id, NULL); \
        assert_string_equal(str(friendly), found_str); \
        assert_int_equal(value, found_id); \
        assert_int_equal(value, from_hex_str); \
        assert_int_equal(value, from_nice_str); \
    }

single_item_test(rsa, TPM_ALG_RSA)
/*
 * sha sha1 is it's own test, as alg to string
 * can return either, based on the map ordering.
 *
 */
single_item_test(hmac, TPM_ALG_HMAC)
single_item_test(aes, TPM_ALG_AES)
single_item_test(mgf1, TPM_ALG_MGF1)
single_item_test(keyedhash, TPM_ALG_KEYEDHASH)
single_item_test(xor, TPM_ALG_XOR)
single_item_test(sha256, TPM_ALG_SHA256)
single_item_test(sha384, TPM_ALG_SHA384)
single_item_test(sha512, TPM_ALG_SHA512)
single_item_test(null, TPM_ALG_NULL)
single_item_test(sm3_256, TPM_ALG_SM3_256)
single_item_test(sm4, TPM_ALG_SM4)
single_item_test(rsassa, TPM_ALG_RSASSA)
single_item_test(rsaes, TPM_ALG_RSAES)
single_item_test(rsapss, TPM_ALG_RSAPSS)
single_item_test(oaep, TPM_ALG_OAEP)
single_item_test(ecdsa, TPM_ALG_ECDSA)
single_item_test(ecdh, TPM_ALG_ECDH)
single_item_test(ecdaa, TPM_ALG_ECDAA)
single_item_test(sm2, TPM_ALG_SM2)
single_item_test(ecschnorr, TPM_ALG_ECSCHNORR)
single_item_test(ecmqv, TPM_ALG_ECMQV)
single_item_test(kdf1_sp800_56a, TPM_ALG_KDF1_SP800_56A)
single_item_test(kdf2, TPM_ALG_KDF2)
single_item_test(kdf1_sp800_108, TPM_ALG_KDF1_SP800_108)
single_item_test(ecc, TPM_ALG_ECC)
single_item_test(symcipher, TPM_ALG_SYMCIPHER)
single_item_test(camellia, TPM_ALG_CAMELLIA)
single_item_test(sha3_256, TPM_ALG_SHA3_256)
single_item_test(sha3_384, TPM_ALG_SHA3_384)
single_item_test(sha3_512, TPM_ALG_SHA3_512)
single_item_test(ctr, TPM_ALG_CTR)
single_item_test(ofb, TPM_ALG_OFB)
single_item_test(cbc, TPM_ALG_CBC)
single_item_test(cfb, TPM_ALG_CFB)
single_item_test(ecb, TPM_ALG_ECB)

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

    const char *sha_found_str = tpm2_alg_util_algtostr(TPM_ALG_SHA);

    TPM_ALG_ID sha1_found_id = tpm2_alg_util_strtoalg("sha1");
    const char *sha1_found_str = tpm2_alg_util_algtostr(TPM_ALG_SHA1);

    TPM_ALG_ID sha_from_hex_str = tpm2_alg_util_from_optarg("sha");

    char buf[256];
    snprintf(buf, sizeof(buf), "0x%X", TPM_ALG_SHA);
    TPM_ALG_ID sha_from_nice_str = tpm2_alg_util_from_optarg(buf);

    TPM_ALG_ID sha1_from_hex_str = tpm2_alg_util_from_optarg("sha1");

    snprintf(buf, sizeof(buf), "0x%X", TPM_ALG_SHA1);
    TPM_ALG_ID sha1_from_nice_str = tpm2_alg_util_from_optarg(buf);

    assert_int_equal(TPM_ALG_SHA, sha_found_id);
    assert_int_equal(TPM_ALG_SHA, sha_from_hex_str);
    assert_int_equal(TPM_ALG_SHA, sha_from_nice_str);

    assert_int_equal(TPM_ALG_SHA1, sha1_found_id);
    assert_int_equal(TPM_ALG_SHA, sha1_from_hex_str);
    assert_int_equal(TPM_ALG_SHA, sha1_from_nice_str);

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
    TPM_ALG_RSA,
    TPM_ALG_SHA,
    TPM_ALG_SHA1,
    TPM_ALG_HMAC,
    TPM_ALG_AES,
    TPM_ALG_MGF1,
    TPM_ALG_KEYEDHASH,
    TPM_ALG_XOR,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
    TPM_ALG_NULL,
    TPM_ALG_SM3_256,
    TPM_ALG_SM4,
    TPM_ALG_RSASSA,
    TPM_ALG_RSAES,
    TPM_ALG_RSAPSS,
    TPM_ALG_OAEP,
    TPM_ALG_ECDSA,
    TPM_ALG_ECDH,
    TPM_ALG_ECDAA,
    TPM_ALG_SM2,
    TPM_ALG_ECSCHNORR,
    TPM_ALG_ECMQV,
    TPM_ALG_KDF1_SP800_56A,
    TPM_ALG_KDF2,
    TPM_ALG_KDF1_SP800_108,
    TPM_ALG_ECC,
    TPM_ALG_SYMCIPHER,
    TPM_ALG_CAMELLIA,
    TPM_ALG_SHA3_256,
    TPM_ALG_SHA3_384,
    TPM_ALG_SHA3_512,
    TPM_ALG_CTR,
    TPM_ALG_OFB,
    TPM_ALG_CBC,
    TPM_ALG_CFB,
    TPM_ALG_ECB };

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

/* Test the digest specification langauge */

#define HASH_SHA    "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"
#define HASH_SHA256 "c324d5e9514f00b1a42052666721fb0911090ca197bf831f6568e735bc8522c3"
#define HASH_SHA384 "8effdabfe14416214a250f935505250bd991f106065d899db6e19bdc8bf648f3ac0f1935c4f65fe8f798289b1a0d1e06"
#define HASH_SHA512 "0cf9180a764aba863a67b6d72f0918bc131c6772642cb2dce5a34f0a702f9470ddc2bf125c12198b1995c233c34b4afd346c54a2334c350a948a51b6e8b4e6b6"

#define test_digest(digest, expected_hash_str, expected_alg, expected_hash_len) \
    do { \
        UINT16 _expected_hash_len = expected_hash_len; \
        BYTE expected_hash[expected_hash_len]; \
        int rc = tpm2_util_hex_to_byte_structure(expected_hash_str, &_expected_hash_len, expected_hash); \
        assert_true(rc == 0); \
        \
        assert_int_equal(digest->hashAlg, expected_alg); \
        assert_memory_equal((BYTE *)&digest->digest, expected_hash, \
                expected_hash_len); \
    } while (0)

#define test_digest_sha1(digest)    test_digest(digest, HASH_SHA, TPM_ALG_SHA1, SHA1_DIGEST_SIZE)
#define test_digest_sha256(digest)  test_digest(digest, HASH_SHA256, TPM_ALG_SHA256, SHA256_DIGEST_SIZE)
#define test_digest_sha384(digest)  test_digest(digest, HASH_SHA384, TPM_ALG_SHA384, SHA384_DIGEST_SIZE)
#define test_digest_sha512(digest)  test_digest(digest, HASH_SHA512, TPM_ALG_SHA512, SHA512_DIGEST_SIZE)

#define get_single_digest_pcr_parse_test(friendly_hash) \
		cmocka_unit_test(test_pcr_parse_digest_list_##friendly_hash)

#define add_single_digest_pcr_parse_test(pcrindex, friendly_hash, hash_value, hash_id, hash_size) \
    static void test_pcr_parse_digest_list_##friendly_hash(void **state) { \
        (void) state; \
        \
        char mutable_1[] = str(pcrindex)":"str(friendly_hash)"="hash_value; \
        tpm2_pcr_digest_spec digest_spec[1]; \
        char *optstr[1] = { \
            mutable_1 \
        }; \
        \
        bool res = pcr_parse_digest_list(optstr, 1, digest_spec); \
        assert_true(res); \
        \
        TPMT_HA *digest = &digest_spec->digests.digests[0]; \
        test_digest(digest, hash_value, hash_id, hash_size); \
    }

add_single_digest_pcr_parse_test(4, sha, HASH_SHA,
        TPM_ALG_SHA1, SHA1_DIGEST_SIZE)

add_single_digest_pcr_parse_test(9, sha256, HASH_SHA256,
        TPM_ALG_SHA256, SHA256_DIGEST_SIZE)

add_single_digest_pcr_parse_test(67, sha384, HASH_SHA384,
        TPM_ALG_SHA384, SHA384_DIGEST_SIZE)

add_single_digest_pcr_parse_test(21, sha512, HASH_SHA512,
        TPM_ALG_SHA512, SHA512_DIGEST_SIZE)

static void test_pcr_parse_digest_list_many_items(void **state) {
    (void) state;

    char mutable_1[] = "12:sha="HASH_SHA;
    char mutable_2[] = "5:sha256="HASH_SHA256;
    char mutable_3[] = "7:sha512="HASH_SHA512;
    char *optstr[] = {
        mutable_1,
        mutable_2,
        mutable_3
    };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_true(res);

    size_t i;
    for (i=0; i < ARRAY_LEN(digest_spec); i++) {
        tpm2_pcr_digest_spec *dspec = &digest_spec[i];

        /* each pcr only has 1 alg hash specified */
        assert_int_equal(dspec->digests.count, 1);

        TPMT_HA *digest = &dspec->digests.digests[0];

        switch (i) {
        case 0:
            assert_int_equal(dspec->pcr_index, 12);
            test_digest_sha1(digest);
            break;
        case 1:
            assert_int_equal(dspec->pcr_index, 5);
            test_digest_sha256(digest);
            break;
        case 2:
            assert_int_equal(dspec->pcr_index, 7);
            test_digest_sha512(digest);
            break;
        default:
            fail_msg("Missing algorithm test for: %s", optstr[i]);
        }
    }
}

static void test_pcr_parse_digest_list_compound(void **state) {
    (void) state;

    char mutable_1[] = "12:sha="HASH_SHA",sha256="HASH_SHA256",sha512="HASH_SHA512;
    char *optstr[] = {
        mutable_1,
    };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_true(res);

    tpm2_pcr_digest_spec *dspec = &digest_spec[0];

    assert_int_equal(12, dspec->pcr_index);
    assert_int_equal(3, dspec->digests.count);

    size_t i;
    for (i=0; i < dspec->digests.count; i++) {
        TPMT_HA *digest = &dspec->digests.digests[i];

        switch (i) {
        case 0:
            test_digest_sha1(digest);
            break;
        case 1:
            test_digest_sha256(digest);
            break;
        case 2:
            test_digest_sha512(digest);
            break;
        default:
            fail_msg("Missing algorithm test for: %u", dspec->digests.digests[i].hashAlg);
        }
    }
}

static void test_pcr_parse_digest_list_bad(void **state) {
    (void) state;

    char mutable_1[] = "12";
    char *optstr[] = {
        mutable_1,
    };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_2[] = "12:sha256";
    optstr[0] = mutable_2;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_3[] = "12:sha256=";
    optstr[0] = mutable_3;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_4[] = "12:sha256="HASH_SHA;
    optstr[0] = mutable_4;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_5[] = "12:sha256="HASH_SHA512;
    optstr[0] = mutable_5;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_6[] = "12:";
    optstr[0] = mutable_6;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);
}

static void test_pcr_parse_digest_list_bad_alg(void **state) {
    (void) state;

    char mutable_1[] = "12";
    char *optstr[] = {
        mutable_1,
    };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_2[] = "12:rsa="HASH_SHA;
    optstr[0] = mutable_2;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);
}

static void test_tpm2_alg_util_get_hash_size(void **state) {
    (void) state;

    UINT16 hsize = tpm2_alg_util_get_hash_size(TPM_ALG_SHA1);
    assert_int_equal(hsize, SHA1_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM_ALG_SHA256);
    assert_int_equal(hsize, SHA256_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM_ALG_SHA384);
    assert_int_equal(hsize, SHA384_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM_ALG_SHA512);
    assert_int_equal(hsize, SHA512_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM_ALG_SM3_256);
    assert_int_equal(hsize, SM3_256_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM_ALG_RSA);
    assert_int_equal(hsize, 0);
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
        cmocka_unit_test(test_tpm2_alg_util_everything_is_tested),
        get_single_digest_pcr_parse_test(sha),
        get_single_digest_pcr_parse_test(sha256),
        get_single_digest_pcr_parse_test(sha384),
        get_single_digest_pcr_parse_test(sha512),
        cmocka_unit_test(test_pcr_parse_digest_list_many_items),
        cmocka_unit_test(test_pcr_parse_digest_list_compound),
        cmocka_unit_test(test_pcr_parse_digest_list_bad),
        cmocka_unit_test(test_pcr_parse_digest_list_bad_alg),
        cmocka_unit_test(test_tpm2_alg_util_get_hash_size)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
