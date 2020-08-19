/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_util.h"
#include "tpm2_alg_util.h"

#define xstr(s) str(s)
#define str(s) #s

#define single_item_test_get(friendly) \
    cmocka_unit_test(test_tpm2_alg_util_convert_##friendly)

#define nv_single_item_test2(friendly, value, flags) \
    static void test_tpm2_alg_util_convert_##friendly(void **state) { \
    \
        (void)state; \
    \
        TPM2_ALG_ID found_id = tpm2_alg_util_strtoalg(str(friendly), flags); \
        const char *found_str = tpm2_alg_util_algtostr(value, flags); \
        char str_value[256]; \
        snprintf(str_value, sizeof(str_value), "0x%X", value); \
        TPM2_ALG_ID from_hex_str = tpm2_alg_util_from_optarg(str_value, flags);    \
        TPM2_ALG_ID from_nice_str = tpm2_alg_util_from_optarg(str(friendly), flags);    \
        \
        assert_ptr_not_equal(found_id, NULL); \
        assert_string_equal(str(friendly), found_str); \
        assert_int_equal(value, found_id); \
        assert_int_equal(value, from_hex_str); \
        assert_int_equal(value, from_nice_str); \
    }

#define nv_single_item_test(friendly, value) nv_single_item_test2(friendly, value, tpm2_alg_util_flags_any)

nv_single_item_test(rsa, TPM2_ALG_RSA)
/*
 * sha sha1 is it's own test, as alg to string
 * can return either, based on the map ordering.
 *
 */
nv_single_item_test(hmac, TPM2_ALG_HMAC)
nv_single_item_test(aes, TPM2_ALG_AES)
nv_single_item_test(mgf1, TPM2_ALG_MGF1)
nv_single_item_test(keyedhash, TPM2_ALG_KEYEDHASH)
nv_single_item_test(xor, TPM2_ALG_XOR)
nv_single_item_test(sha256, TPM2_ALG_SHA256)
nv_single_item_test(sha384, TPM2_ALG_SHA384)
nv_single_item_test(sha512, TPM2_ALG_SHA512)
nv_single_item_test(null, TPM2_ALG_NULL)
nv_single_item_test(sm3_256, TPM2_ALG_SM3_256)
nv_single_item_test(sm4, TPM2_ALG_SM4)
nv_single_item_test(rsassa, TPM2_ALG_RSASSA)
nv_single_item_test(rsaes, TPM2_ALG_RSAES)
nv_single_item_test(rsapss, TPM2_ALG_RSAPSS)
nv_single_item_test(oaep, TPM2_ALG_OAEP)
nv_single_item_test(ecdsa, TPM2_ALG_ECDSA)
nv_single_item_test(ecdh, TPM2_ALG_ECDH)
nv_single_item_test(ecdaa, TPM2_ALG_ECDAA)
nv_single_item_test(sm2, TPM2_ALG_SM2)
nv_single_item_test(ecschnorr, TPM2_ALG_ECSCHNORR)
nv_single_item_test(ecmqv, TPM2_ALG_ECMQV)
nv_single_item_test(kdf1_sp800_56a, TPM2_ALG_KDF1_SP800_56A)
nv_single_item_test(kdf2, TPM2_ALG_KDF2)
nv_single_item_test(kdf1_sp800_108, TPM2_ALG_KDF1_SP800_108)
nv_single_item_test(ecc, TPM2_ALG_ECC)
nv_single_item_test(symcipher, TPM2_ALG_SYMCIPHER)
nv_single_item_test(camellia, TPM2_ALG_CAMELLIA)
nv_single_item_test(sha3_256, TPM2_ALG_SHA3_256)
nv_single_item_test(sha3_384, TPM2_ALG_SHA3_384)
nv_single_item_test(sha3_512, TPM2_ALG_SHA3_512)
nv_single_item_test(ctr, TPM2_ALG_CTR)
nv_single_item_test(ofb, TPM2_ALG_OFB)
nv_single_item_test(cbc, TPM2_ALG_CBC)
nv_single_item_test(cfb, TPM2_ALG_CFB)
nv_single_item_test(ecb, TPM2_ALG_ECB)

typedef struct find_unk_data find_unk_data;
struct find_unk_data {
    TPM2_ALG_ID *ids;
    size_t len;
};

static void test_tpm2_alg_util_sha1_test(void **state) {

    (void) state;

    TPM2_ALG_ID sha1_found_id = tpm2_alg_util_strtoalg("sha1",
            tpm2_alg_util_flags_hash);
    const char *sha1_found_str = tpm2_alg_util_algtostr(TPM2_ALG_SHA1,
            tpm2_alg_util_flags_hash);

    char buf[256];

    TPM2_ALG_ID sha1_from_hex_str = tpm2_alg_util_from_optarg("sha1",
            tpm2_alg_util_flags_hash);

    snprintf(buf, sizeof(buf), "0x%X", TPM2_ALG_SHA1);
    TPM2_ALG_ID sha1_from_nice_str = tpm2_alg_util_from_optarg(buf,
            tpm2_alg_util_flags_hash);

    assert_int_equal(TPM2_ALG_SHA1, sha1_found_id);
    assert_int_equal(TPM2_ALG_SHA1, sha1_from_hex_str);
    assert_int_equal(TPM2_ALG_SHA1, sha1_from_nice_str);

    bool sha1_pass = false;
    sha1_pass = !strcmp(sha1_found_str, "sha1");
    assert_true(sha1_pass);
}

/* Test the digest specification language */

#define HASH_SHA1    "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"
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

#define test_digest_sha1(digest)    test_digest(digest, HASH_SHA1, TPM2_ALG_SHA1, TPM2_SHA1_DIGEST_SIZE)
#define test_digest_sha256(digest)  test_digest(digest, HASH_SHA256, TPM2_ALG_SHA256, TPM2_SHA256_DIGEST_SIZE)
#define test_digest_sha384(digest)  test_digest(digest, HASH_SHA384, TPM2_ALG_SHA384, TPM2_SHA384_DIGEST_SIZE)
#define test_digest_sha512(digest)  test_digest(digest, HASH_SHA512, TPM2_ALG_SHA512, TPM2_SHA512_DIGEST_SIZE)

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

add_single_digest_pcr_parse_test(4, sha1, HASH_SHA1, TPM2_ALG_SHA1,
        TPM2_SHA1_DIGEST_SIZE)

add_single_digest_pcr_parse_test(9, sha256, HASH_SHA256, TPM2_ALG_SHA256,
        TPM2_SHA256_DIGEST_SIZE)

add_single_digest_pcr_parse_test(6, sha384, HASH_SHA384, TPM2_ALG_SHA384,
        TPM2_SHA384_DIGEST_SIZE)

add_single_digest_pcr_parse_test(21, sha512, HASH_SHA512, TPM2_ALG_SHA512,
        TPM2_SHA512_DIGEST_SIZE)

static void test_pcr_parse_digest_list_many_items(void **state) {
    (void) state;

    char mutable_1[] = "12:sha1="HASH_SHA1;
    char mutable_2[] = "5:sha256="HASH_SHA256;
    char mutable_3[] = "7:sha512="HASH_SHA512;
    char *optstr[] = { mutable_1, mutable_2, mutable_3 };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec),
            digest_spec);
    assert_true(res);

    size_t i;
    for (i = 0; i < ARRAY_LEN(digest_spec); i++) {
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

    char mutable_1[] =
            "12:sha1="HASH_SHA1",sha256="HASH_SHA256",sha512="HASH_SHA512;
    char *optstr[] = { mutable_1, };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec),
            digest_spec);
    assert_true(res);

    tpm2_pcr_digest_spec *dspec = &digest_spec[0];

    assert_int_equal(12, dspec->pcr_index);
    assert_int_equal(3, dspec->digests.count);

    size_t i;
    for (i = 0; i < dspec->digests.count && i < TPM2_NUM_PCR_BANKS; i++) {
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
            fail_msg("Missing algorithm test for: %u", digest->hashAlg);
        }
    }
}

static void test_pcr_parse_digest_list_bad(void **state) {
    (void) state;

    char mutable_1[] = "12";
    char *optstr[] = { mutable_1, };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec),
            digest_spec);
    assert_false(res);

    char mutable_2[] = "12:sha256";
    optstr[0] = mutable_2;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_3[] = "12:sha256=";
    optstr[0] = mutable_3;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);

    char mutable_4[] = "12:sha256="HASH_SHA1;
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
    char *optstr[] = { mutable_1, };

    tpm2_pcr_digest_spec digest_spec[ARRAY_LEN(optstr)];
    bool res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec),
            digest_spec);
    assert_false(res);

    char mutable_2[] = "12:rsa="HASH_SHA1;
    optstr[0] = mutable_2;
    res = pcr_parse_digest_list(optstr, ARRAY_LEN(digest_spec), digest_spec);
    assert_false(res);
}

static void test_tpm2_alg_util_get_hash_size(void **state) {
    (void) state;

    UINT16 hsize = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA1);
    assert_int_equal(hsize, TPM2_SHA1_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA256);
    assert_int_equal(hsize, TPM2_SHA256_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA384);
    assert_int_equal(hsize, TPM2_SHA384_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA512);
    assert_int_equal(hsize, TPM2_SHA512_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM2_ALG_SM3_256);
    assert_int_equal(hsize, TPM2_SM3_256_DIGEST_SIZE);

    hsize = tpm2_alg_util_get_hash_size(TPM2_ALG_RSA);
    assert_int_equal(hsize, 0);
}

static void test_tpm2_alg_util_flags_sig(void **state) {
    UNUSED(state);

    TPM2_ALG_ID good_algs[] = {
        TPM2_ALG_RSASSA,
        TPM2_ALG_RSAPSS,
        TPM2_ALG_HMAC,
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(good_algs); i++) {
        TPM2_ALG_ID id = good_algs[i];
        const char *name = tpm2_alg_util_algtostr(id, tpm2_alg_util_flags_sig);
        assert_non_null(name);
    }

    const char *name = tpm2_alg_util_algtostr(TPM2_ALG_AES,
            tpm2_alg_util_flags_sig);
    assert_null(name);
}

static void test_tpm2_alg_util_flags_enc_scheme(void **state) {
    UNUSED(state);

    TPM2_ALG_ID good_algs[] = {
        TPM2_ALG_RSAES,
        TPM2_ALG_OAEP,
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(good_algs); i++) {
        TPM2_ALG_ID id = good_algs[i];
        const char *name = tpm2_alg_util_algtostr(id,
                tpm2_alg_util_flags_enc_scheme);
        assert_non_null(name);
    }

    const char *name = tpm2_alg_util_algtostr(TPM2_ALG_AES,
            tpm2_alg_util_flags_enc_scheme);
    assert_null(name);
}

static void test_tpm2_alg_util_flags_hash(void **state) {
    UNUSED(state);

    TPM2_ALG_ID good_algs[] = {
        TPM2_ALG_SHA1,
        TPM2_ALG_SHA256,
        TPM2_ALG_SHA384,
        TPM2_ALG_SHA512,
        TPM2_ALG_SM3_256
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(good_algs); i++) {
        TPM2_ALG_ID id = good_algs[i];
        const char *name = tpm2_alg_util_algtostr(id, tpm2_alg_util_flags_hash);
        assert_non_null(name);
    }

    const char *name = tpm2_alg_util_algtostr(TPM2_ALG_AES,
            tpm2_alg_util_flags_hash);
    assert_null(name);
}

static void test_extended_alg_rsa2048_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa2048", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_NULL);
}

static void test_extended_alg_rsa2048_aes128cfb_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa2048:aes128cfb", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_NULL);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.sym, TPM2_ALG_CFB);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_rsa2048_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("rsa2048", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_NULL);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.sym, TPM2_ALG_CFB);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_rsa_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_NULL);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->algorithm, TPM2_ALG_NULL);
}

static void test_extended_alg_rsa1024_rsaes_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("rsa1024:rsaes", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 1024);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_RSAES);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.sym, TPM2_ALG_CFB);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_rsa1024_rsaes(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa1024:rsaes", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 1024);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_RSAES);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->algorithm, TPM2_ALG_NULL);
}

static void test_extended_alg_rsa_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("rsa", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_NULL);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.aes, TPM2_ALG_CFB);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_rsa_rsapss(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa:rsapss", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_RSAPSS);

    TPMT_SYM_DEF_OBJECT *s = &r->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.aes, TPM2_ALG_CFB);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_rsa_rsassa_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa:rsassa", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    TPMS_RSA_PARMS *r = &pub.publicArea.parameters.rsaDetail;
    assert_int_equal(r->exponent, 0);
    assert_int_equal(r->keyBits, 2048);
    assert_int_equal(r->scheme.scheme, TPM2_ALG_RSASSA);

    TPMS_SIG_SCHEME_RSASSA *s = &r->scheme.details.rsassa;
    assert_int_equal(s->hashAlg, TPM2_ALG_SHA256);
}

static void test_extended_alg_ecc256_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("ecc256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P256);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);
}

static void test_extended_alg_ecc256_aes128cbc_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("ecc256:aes128cbc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P256);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);

    TPMT_SYM_DEF_OBJECT *s = &e->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.sym, TPM2_ALG_CBC);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_ecc384_ecdaa4_sha256_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("ecc384:ecdaa4-sha256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_ECDAA);

    assert_int_equal(e->curveID, TPM2_ECC_NIST_P384);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);

    TPMS_SIG_SCHEME_ECDAA *a = &e->scheme.details.ecdaa;
    assert_int_equal(a->count, 4);
    assert_int_equal(a->hashAlg, TPM2_ALG_SHA256);
}

static void test_extended_alg_ecc384_ecdaa4_sha256(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("ecc384:ecdaa4-sha256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_ECDAA);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P384);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);

    TPMS_SIG_SCHEME_ECDAA *a = &e->scheme.details.ecdaa;
    assert_int_equal(a->count, 4);
    assert_int_equal(a->hashAlg, TPM2_ALG_SHA256);

    TPMT_SYM_DEF_OBJECT *s = &e->symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.sym, TPM2_ALG_CFB);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_ecc256_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("ecc256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P256);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);
}

static void test_extended_alg_ecc_non_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("ecc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P256);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);
}

static void test_extended_alg_ecc_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("ecc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P256);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);
}

static void test_extended_alg_ecc_ecdsa_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("ecc:ecdaa", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_ECC);

    TPMS_ECC_PARMS *e = &pub.publicArea.parameters.eccDetail;
    assert_int_equal(e->scheme.scheme, TPM2_ALG_ECDAA);
    assert_int_equal(e->curveID, TPM2_ECC_NIST_P256);
    assert_int_equal(e->kdf.scheme, TPM2_ALG_NULL);
    assert_int_equal(e->kdf.details.mgf1.hashAlg, 0);

    TPMS_SIG_SCHEME_ECDAA *a = &e->scheme.details.ecdaa;
    assert_int_equal(a->count, 0);
    assert_int_equal(a->hashAlg, TPM2_ALG_SHA256);
}

static void test_extended_alg_xor_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("xor", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMT_KEYEDHASH_SCHEME *s = &pub.publicArea.parameters.keyedHashDetail.scheme;
    assert_int_equal(s->scheme, TPM2_ALG_XOR);
    assert_int_equal(s->details.exclusiveOr.hashAlg, TPM2_ALG_SHA256);
    assert_int_equal(s->details.exclusiveOr.kdf, TPM2_ALG_KDF1_SP800_108);
}

static void test_extended_alg_xorsha256_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("xor:sha256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMT_KEYEDHASH_SCHEME *s = &pub.publicArea.parameters.keyedHashDetail.scheme;
    assert_int_equal(s->scheme, TPM2_ALG_XOR);
    assert_int_equal(s->details.exclusiveOr.hashAlg, TPM2_ALG_SHA256);
    assert_int_equal(s->details.exclusiveOr.kdf, TPM2_ALG_KDF1_SP800_108);
}

static void test_extended_alg_xor(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("xor", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMT_KEYEDHASH_SCHEME *s = &pub.publicArea.parameters.keyedHashDetail.scheme;
    assert_int_equal(s->scheme, TPM2_ALG_XOR);
    assert_int_equal(s->details.exclusiveOr.hashAlg, TPM2_ALG_SHA256);
    assert_int_equal(s->details.exclusiveOr.kdf, TPM2_ALG_KDF1_SP800_108);
}

static void test_extended_alg_xorsha256(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("xor:sha256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMT_KEYEDHASH_SCHEME *s = &pub.publicArea.parameters.keyedHashDetail.scheme;
    assert_int_equal(s->scheme, TPM2_ALG_XOR);
    assert_int_equal(s->details.exclusiveOr.hashAlg, TPM2_ALG_SHA256);
    assert_int_equal(s->details.exclusiveOr.kdf, TPM2_ALG_KDF1_SP800_108);
}

static void test_extended_alg_hmac_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("hmac", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMI_ALG_HASH alg =
            pub.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    assert_int_equal(alg, TPM2_ALG_SHA256);
}

static void test_extended_alg_hmac(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("hmac", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMI_ALG_HASH alg =
            pub.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    assert_int_equal(alg, TPM2_ALG_SHA256);
}

static void test_extended_alg_hmacsha384_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("hmac:sha384", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, TPMA_OBJECT_RESTRICTED);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMI_ALG_HASH alg =
            pub.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    assert_int_equal(alg, TPM2_ALG_SHA384);
}

static void test_extended_alg_hmacsha384(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("hmac:sha384", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.objectAttributes, 0);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMI_ALG_HASH alg =
            pub.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    assert_int_equal(alg, TPM2_ALG_SHA384);
}

static void test_extended_alg_aes_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("aes", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.aes, TPM2_ALG_NULL);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_aes(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("aes", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.aes, TPM2_ALG_NULL);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_aes256_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("aes256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 256);
    assert_int_equal(s->mode.aes, TPM2_ALG_NULL);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_aes256(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("aes256", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 256);
    assert_int_equal(s->mode.aes, TPM2_ALG_NULL);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_aes256cbc_restricted(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("aes256cbc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 256);
    assert_int_equal(s->mode.aes, TPM2_ALG_CBC);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_aes256cbc(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = {
        .publicArea = {
            .objectAttributes = TPMA_OBJECT_RESTRICTED
        }
    };

    bool res = tpm2_alg_util_handle_ext_alg("aes256cbc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 256);
    assert_int_equal(s->mode.aes, TPM2_ALG_CBC);
    assert_int_equal(s->algorithm, TPM2_ALG_AES);
}

static void test_extended_alg_keyedhash(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("keyedhash", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_KEYEDHASH);

    TPMS_KEYEDHASH_PARMS *k = &pub.publicArea.parameters.keyedHashDetail;
    assert_int_equal(k->scheme.scheme, TPM2_ALG_NULL);
}

static void test_extended_rsa_camellia(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa:camellia", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.rsaDetail.symmetric;
    assert_int_equal(s->keyBits.aes, 128);
    assert_int_equal(s->mode.aes, TPM2_ALG_NULL);
    assert_int_equal(s->algorithm, TPM2_ALG_CAMELLIA);
}

static void test_extended_rsa_camellia256cbc(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("rsa:camellia256cbc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_RSA);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.rsaDetail.symmetric;
    assert_int_equal(s->keyBits.aes, 256);
    assert_int_equal(s->mode.aes, TPM2_ALG_CBC);
    assert_int_equal(s->algorithm, TPM2_ALG_CAMELLIA);
}

static void test_extended_camellia192cbc(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("camellia192cbc", &pub);
    assert_true(res);

    assert_int_equal(pub.publicArea.type, TPM2_ALG_SYMCIPHER);

    TPMT_SYM_DEF_OBJECT *s = &pub.publicArea.parameters.symDetail.sym;
    assert_int_equal(s->keyBits.aes, 192);
    assert_int_equal(s->mode.aes, TPM2_ALG_CBC);
    assert_int_equal(s->algorithm, TPM2_ALG_CAMELLIA);
}

static void test_extended_alg_bad(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC pub = { 0 };

    bool res = tpm2_alg_util_handle_ext_alg("ecc256funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("ecc256:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("rsafunnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("rsa:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("rsa2048funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("rsa2048:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("aesfunnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("aes:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("aes128funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("aes128:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("xorfunnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("xor:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("hmacfunnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("hmac:funnytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("keyedhashfunytexthere", &pub);
    assert_false(res);

    res = tpm2_alg_util_handle_ext_alg("keyedhash:funnytexthere", &pub);
    assert_false(res);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        single_item_test_get(rsa),
        cmocka_unit_test(test_tpm2_alg_util_sha1_test),
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
        get_single_digest_pcr_parse_test(sha1),
        get_single_digest_pcr_parse_test(sha256),
        get_single_digest_pcr_parse_test(sha384),
        get_single_digest_pcr_parse_test(sha512),
        cmocka_unit_test(test_pcr_parse_digest_list_many_items),
        cmocka_unit_test(test_pcr_parse_digest_list_compound),
        cmocka_unit_test(test_pcr_parse_digest_list_bad),
        cmocka_unit_test(test_pcr_parse_digest_list_bad_alg),
        cmocka_unit_test(test_tpm2_alg_util_get_hash_size),
        cmocka_unit_test(test_tpm2_alg_util_flags_sig),
        cmocka_unit_test(test_tpm2_alg_util_flags_enc_scheme),
        cmocka_unit_test(test_tpm2_alg_util_flags_hash),
        cmocka_unit_test(test_extended_alg_rsa2048_non_restricted),
        cmocka_unit_test(test_extended_alg_rsa2048_restricted),
        cmocka_unit_test(test_extended_alg_rsa_non_restricted),
        cmocka_unit_test(test_extended_alg_rsa_restricted),
        cmocka_unit_test(test_extended_alg_rsa1024_rsaes_restricted),
        cmocka_unit_test(test_extended_alg_rsa1024_rsaes),
        cmocka_unit_test(test_extended_alg_rsa_rsapss),
        cmocka_unit_test(test_extended_alg_rsa_rsassa_non_restricted),
        cmocka_unit_test(test_extended_alg_rsa2048_aes128cfb_non_restricted),
        cmocka_unit_test(test_extended_alg_ecc256_non_restricted),
        cmocka_unit_test(test_extended_alg_ecc256_aes128cbc_non_restricted),
        cmocka_unit_test(test_extended_alg_ecc384_ecdaa4_sha256_non_restricted),
        cmocka_unit_test(test_extended_alg_ecc384_ecdaa4_sha256),
        cmocka_unit_test(test_extended_alg_ecc256_restricted),
        cmocka_unit_test(test_extended_alg_ecc_non_restricted),
        cmocka_unit_test(test_extended_alg_ecc_restricted),
        cmocka_unit_test(test_extended_alg_ecc_ecdsa_restricted),
        cmocka_unit_test(test_extended_alg_xor_restricted),
        cmocka_unit_test(test_extended_alg_xor),
        cmocka_unit_test(test_extended_alg_xorsha256_restricted),
        cmocka_unit_test(test_extended_alg_xorsha256),
        cmocka_unit_test(test_extended_alg_hmac_restricted),
        cmocka_unit_test(test_extended_alg_hmac),
        cmocka_unit_test(test_extended_alg_hmacsha384_restricted),
        cmocka_unit_test(test_extended_alg_hmacsha384),
        cmocka_unit_test(test_extended_alg_aes_restricted),
        cmocka_unit_test(test_extended_alg_aes),
        cmocka_unit_test(test_extended_alg_aes256_restricted),
        cmocka_unit_test(test_extended_alg_aes256),
        cmocka_unit_test(test_extended_alg_aes256cbc_restricted),
        cmocka_unit_test(test_extended_alg_aes256cbc),
        cmocka_unit_test(test_extended_alg_keyedhash),
        cmocka_unit_test(test_extended_rsa_camellia),
        cmocka_unit_test(test_extended_rsa_camellia256cbc),
        cmocka_unit_test(test_extended_camellia192cbc),
        cmocka_unit_test(test_extended_alg_bad),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
