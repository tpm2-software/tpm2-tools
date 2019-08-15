/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_attr_util.h"

#define test_nv_strtoattr_get(set) \
    cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_##set)

#define nv_single_item_test(argstr, set) \
    static void test_tpm2_attr_util_nv_strtoattr_##set(void **state) { \
        \
        (void)state; \
    \
        TPMA_NV nvattrs = 0; \
        /* make mutable strings for strtok_r */ \
        char arg[] = argstr; \
        bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs); \
        assert_true(res); \
        assert_true(nvattrs == set); \
    }

nv_single_item_test("authread", TPMA_NV_AUTHREAD);
nv_single_item_test("authwrite", TPMA_NV_AUTHWRITE);
nv_single_item_test("clear_stclear", TPMA_NV_CLEAR_STCLEAR);
nv_single_item_test("globallock", TPMA_NV_GLOBALLOCK);
nv_single_item_test("no_da", TPMA_NV_NO_DA);
nv_single_item_test("orderly", TPMA_NV_ORDERLY);
nv_single_item_test("ownerread", TPMA_NV_OWNERREAD);
nv_single_item_test("ownerwrite", TPMA_NV_OWNERWRITE);
nv_single_item_test("platformcreate", TPMA_NV_PLATFORMCREATE);
nv_single_item_test("policyread", TPMA_NV_POLICYREAD);
nv_single_item_test("policywrite", TPMA_NV_POLICYWRITE);
nv_single_item_test("policydelete", TPMA_NV_POLICY_DELETE);
nv_single_item_test("ppread", TPMA_NV_PPREAD);
nv_single_item_test("ppwrite", TPMA_NV_PPWRITE);
nv_single_item_test("readlocked", TPMA_NV_READLOCKED);
nv_single_item_test("read_stclear", TPMA_NV_READ_STCLEAR);
nv_single_item_test("writeall", TPMA_NV_WRITEALL);
nv_single_item_test("writedefine", TPMA_NV_WRITEDEFINE);
nv_single_item_test("writelocked", TPMA_NV_WRITELOCKED);
nv_single_item_test("write_stclear", TPMA_NV_WRITE_STCLEAR);
nv_single_item_test("written", TPMA_NV_WRITTEN);

static void test_tpm2_attr_util_nv_strtoattr_nt_good(void **state) {
    (void) state;

    TPMA_NV nvattrs = 0;

    char arg[] = "nt=0x1";
    bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs);
    assert_true(res);
    assert_true((nvattrs & TPMA_NV_TPM2_NT_MASK) >> TPMA_NV_TPM2_NT_SHIFT ==
        0x1);
}

static void test_tpm2_attr_util_nv_strtoattr_nt_bad(void **state) {
    (void) state;

    TPMA_NV nvattrs = 0;

    char arg[] = "nt=16";
    bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs);
    assert_false(res);
}

static void test_tpm2_attr_util_nv_strtoattr_nt_malformed(void **state) {
    (void) state;

    TPMA_NV nvattrs = 0;

    char arg[] = "nt=";
    bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs);
    assert_false(res);

    char arg1[] = "nt";
    res = tpm2_attr_util_nv_strtoattr(arg1, &nvattrs);
    assert_false(res);
}

static void test_tpm2_attr_util_nv_strtoattr_option_no_option(void **state) {
    (void) state;

    TPMA_NV nvattrs = 0;

    char arg[] = "authread=";
    bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs);
    assert_false(res);

    char arg1[] = "authread=0x1";
    res = tpm2_attr_util_nv_strtoattr(arg1, &nvattrs);
    assert_false(res);
}

static void test_tpm2_attr_util_nv_strtoattr_multiple_good(void **state) {
    (void) state;

    TPMA_NV nvattrs = 0;

    char arg[] = "authread|authwrite|nt=0x4";
    bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs);
    assert_true(res);
    assert_true((nvattrs & TPMA_NV_TPM2_NT_MASK) >> TPMA_NV_TPM2_NT_SHIFT ==
        0x4);
    assert_true(nvattrs & TPMA_NV_AUTHREAD);
    assert_true(nvattrs & TPMA_NV_AUTHWRITE);
}

static void test_tpm2_attr_util_nv_strtoattr_token_unknown(void **state) {
    (void) state;

    TPMA_NV nvattrs = 0;

    char arg[] = "authread|authfoo|nt=0x4";
    bool res = tpm2_attr_util_nv_strtoattr(arg, &nvattrs);
    assert_false(res);

    char arg1[] = "foo";
    res = tpm2_attr_util_nv_strtoattr(arg1, &nvattrs);
    assert_false(res);

    char arg2[] = "foo=";
    res = tpm2_attr_util_nv_strtoattr(arg2, &nvattrs);
    assert_false(res);

    /* should be interpreted as the whole thing, no = */
    char arg3[] = "nt:0x4";
    res = tpm2_attr_util_nv_strtoattr(arg3, &nvattrs);
    assert_false(res);
}

#define test_nv_attrtostr(value, expected) \
    static void test_tpm2_nv_util_attrtostr_##value(void **state) { \
    \
        (void) state; \
    \
        TPMA_NV attrs = value; \
        char *str = tpm2_attr_util_nv_attrtostr(attrs); \
        assert_string_equal(str, expected); \
    \
        free(str); \
    }

#define test_nv_attrtostr_get(value) \
		cmocka_unit_test(test_tpm2_nv_util_attrtostr_##value)

test_nv_attrtostr(0, "<none>");
test_nv_attrtostr(TPMA_NV_PPWRITE, "ppwrite")
test_nv_attrtostr(TPMA_NV_OWNERWRITE, "ownerwrite")
test_nv_attrtostr(TPMA_NV_AUTHWRITE, "authwrite")
test_nv_attrtostr(TPMA_NV_POLICYWRITE, "policywrite")
test_nv_attrtostr(TPMA_NV_POLICY_DELETE, "policydelete")
test_nv_attrtostr(TPMA_NV_WRITELOCKED, "writelocked")
test_nv_attrtostr(TPMA_NV_WRITEALL, "writeall")
test_nv_attrtostr(TPMA_NV_WRITEDEFINE, "writedefine")
test_nv_attrtostr(TPMA_NV_WRITE_STCLEAR, "write_stclear")
test_nv_attrtostr(TPMA_NV_GLOBALLOCK, "globallock")
test_nv_attrtostr(TPMA_NV_PPREAD, "ppread")
test_nv_attrtostr(TPMA_NV_OWNERREAD, "ownerread")
test_nv_attrtostr(TPMA_NV_AUTHREAD, "authread")
test_nv_attrtostr(TPMA_NV_POLICYREAD, "policyread")
test_nv_attrtostr(TPMA_NV_NO_DA, "no_da")
test_nv_attrtostr(TPMA_NV_ORDERLY, "orderly")
test_nv_attrtostr(TPMA_NV_CLEAR_STCLEAR, "clear_stclear")
test_nv_attrtostr(TPMA_NV_READLOCKED, "readlocked")
test_nv_attrtostr(TPMA_NV_WRITTEN, "written")
test_nv_attrtostr(TPMA_NV_PLATFORMCREATE, "platformcreate")
test_nv_attrtostr(TPMA_NV_READ_STCLEAR, "read_stclear")

test_nv_attrtostr(0x100, "<reserved(8)>") //bit 8 - reserved
test_nv_attrtostr(0x200, "<reserved(9)>") //bit 9 - reserved

test_nv_attrtostr(0x100000, "<reserved(20)>")  //bit 20 - reserved
test_nv_attrtostr(0x200000, "<reserved(21)>")  //bit 21 - reserved
test_nv_attrtostr(0x400000, "<reserved(22)>")  //bit 22 - reserved
test_nv_attrtostr(0x800000, "<reserved(23)>")  //bit 23- reserved
test_nv_attrtostr(0x1000000, "<reserved(24)>") //bit 24- reserved

test_nv_attrtostr(0x30, "nt=0x3") //bit 24- reserved
test_nv_attrtostr(0x90, "nt=0x9") //bit 24- reserved

#define NV_ALL_FIELDS \
        "ppwrite|ownerwrite|authwrite|policywrite|nt=0xF|<reserved(8)>"  \
        "|<reserved(9)>|policydelete|writelocked|writeall|writedefine"   \
        "|write_stclear|globallock|ppread|ownerread|authread|policyread" \
        "|<reserved(20)>|<reserved(21)>|<reserved(22)>|<reserved(23)>"   \
        "|<reserved(24)>|no_da|orderly|clear_stclear|readlocked|written" \
        "|platformcreate|read_stclear"

test_nv_attrtostr(0xFFFFFFFF, NV_ALL_FIELDS);

#define test_nv_attrtostr_compound(id, value, expected) \
    static void test_tpm2_nv_util_attrtostr_##id(void **state) { \
    \
        (void) state; \
    \
        TPMA_NV attrs = value; \
        char *str = tpm2_attr_util_nv_attrtostr(attrs); \
        assert_string_equal(str, expected); \
    \
        free(str); \
    }

test_nv_attrtostr_compound(stclear_ppwrite,
        TPMA_NV_WRITE_STCLEAR | TPMA_NV_PPWRITE, "ppwrite|write_stclear")
test_nv_attrtostr_compound(stclear_ppwrite_0x30,
        TPMA_NV_WRITE_STCLEAR | TPMA_NV_PPWRITE | 0x30,
        "ppwrite|nt=0x3|write_stclear")
test_nv_attrtostr_compound(platformcreate_ownerread_nt_0x90_0x20000,
        TPMA_NV_PLATFORMCREATE | TPMA_NV_AUTHWRITE | 0x90 | 0x200000,
        "authwrite|nt=0x9|<reserved(21)>|platformcreate")

/*
 * TPMA_OBJECT Tests
 */
#define obj_single_item_test(argstr, set) \
    static void test_tpm2_attr_util_nv_strtoattr_##set(void **state) { \
        \
        (void)state; \
        \
        TPMA_OBJECT objattrs = 0; \
        /* make mutable strings for strtok_r */ \
        char arg[] = argstr; \
        bool res = tpm2_attr_util_obj_strtoattr(arg, &objattrs); \
        assert_true(res); \
        assert_true(objattrs & set); \
    }

#define test_obj_strtoattr_get(set) \
    cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_##set)

obj_single_item_test("fixedtpm", TPMA_OBJECT_FIXEDTPM);
obj_single_item_test("stclear", TPMA_OBJECT_STCLEAR);
obj_single_item_test("fixedparent", TPMA_OBJECT_FIXEDPARENT);
obj_single_item_test("sensitivedataorigin", TPMA_OBJECT_SENSITIVEDATAORIGIN);
obj_single_item_test("userwithauth", TPMA_OBJECT_USERWITHAUTH);
obj_single_item_test("adminwithpolicy", TPMA_OBJECT_ADMINWITHPOLICY);
obj_single_item_test("noda", TPMA_OBJECT_NODA);
obj_single_item_test("encryptedduplication", TPMA_OBJECT_ENCRYPTEDDUPLICATION);
obj_single_item_test("restricted", TPMA_OBJECT_RESTRICTED);
obj_single_item_test("decrypt", TPMA_OBJECT_DECRYPT);
obj_single_item_test("sign", TPMA_OBJECT_SIGN_ENCRYPT);

#define OBJ_ALL_FIELDS \
        "<reserved(0)>|fixedtpm|stclear|<reserved(3)>|fixedparent" \
        "|sensitivedataorigin|userwithauth|adminwithpolicy|<reserved(8)>|" \
        "<reserved(9)>|noda|encryptedduplication|<reserved(12)>|" \
        "<reserved(13)>|<reserved(14)>|<reserved(15)>|restricted|decrypt|" \
        "sign|<reserved(19)>|<reserved(20)>|<reserved(21)>|<reserved(22)>|" \
        "<reserved(23)>|<reserved(24)>|<reserved(25)>|<reserved(26)>|" \
        "<reserved(27)>|<reserved(28)>|<reserved(29)>|<reserved(30)>|" \
        "<reserved(31)>"

#define test_obj_attrtostr(value, expected) \
    static void test_tpm2_obj_util_attrtostr_##value(void **state) { \
    \
        (void) state; \
    \
        TPMA_OBJECT attrs = value; \
        char *str = tpm2_attr_util_obj_attrtostr(attrs); \
        assert_string_equal(str, expected); \
    \
        free(str); \
    }

#define test_obj_attrtostr_get(value) \
        cmocka_unit_test(test_tpm2_obj_util_attrtostr_##value)

test_obj_attrtostr(0xFFFFFFFF, OBJ_ALL_FIELDS);

test_obj_attrtostr(TPMA_OBJECT_FIXEDTPM, "fixedtpm");
test_obj_attrtostr(TPMA_OBJECT_STCLEAR, "stclear");
test_obj_attrtostr(TPMA_OBJECT_FIXEDPARENT, "fixedparent");
test_obj_attrtostr(TPMA_OBJECT_SENSITIVEDATAORIGIN, "sensitivedataorigin");
test_obj_attrtostr(TPMA_OBJECT_USERWITHAUTH, "userwithauth");
test_obj_attrtostr(TPMA_OBJECT_ADMINWITHPOLICY, "adminwithpolicy");
test_obj_attrtostr(TPMA_OBJECT_NODA, "noda");
test_obj_attrtostr(TPMA_OBJECT_ENCRYPTEDDUPLICATION, "encryptedduplication");
test_obj_attrtostr(TPMA_OBJECT_RESTRICTED, "restricted");
test_obj_attrtostr(TPMA_OBJECT_DECRYPT, "decrypt");
test_obj_attrtostr(TPMA_OBJECT_SIGN_ENCRYPT, "sign");

test_obj_attrtostr(TPMA_OBJECT_RESERVED1_MASK, "<reserved(0)>");
test_obj_attrtostr(TPMA_OBJECT_RESERVED2_MASK, "<reserved(3)>");
test_obj_attrtostr(TPMA_OBJECT_RESERVED3_MASK, "<reserved(8)>|<reserved(9)>");
test_obj_attrtostr(TPMA_OBJECT_RESERVED4_MASK, "<reserved(12)>|<reserved(13)>|" \
        "<reserved(14)>|<reserved(15)>");
test_obj_attrtostr(TPMA_OBJECT_RESERVED5_MASK, "<reserved(19)>|<reserved(20)>|" \
        "<reserved(21)>|<reserved(22)>|<reserved(23)>|<reserved(24)>|" \
        "<reserved(25)>|<reserved(26)>|<reserved(27)>|<reserved(28)>|" \
        "<reserved(29)>|<reserved(30)>|<reserved(31)>");

static void test_tpm2_attr_util_obj_strtoattr_multiple_good(void **state) {
    (void) state;

    TPMA_OBJECT objattrs = 0;

    char arg[] = "sign|adminwithpolicy|noda";
    bool res = tpm2_attr_util_obj_strtoattr(arg, &objattrs);
    assert_true(res);
    assert_true(objattrs & TPMA_OBJECT_ADMINWITHPOLICY);
    assert_true(objattrs & TPMA_OBJECT_SIGN_ENCRYPT);
    assert_true(objattrs & TPMA_OBJECT_NODA);

    assert_int_equal(objattrs,
            TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_NODA
                    | TPMA_OBJECT_ADMINWITHPOLICY);
}

static void test_tpm2_attr_util_obj_strtoattr_token_unknown(void **state) {
    (void) state;

    TPMA_OBJECT objattrs = 0;

    char arg[] = "fixedtpm|noda|unknown";
    bool res = tpm2_attr_util_obj_strtoattr(arg, &objattrs);
    assert_false(res);

    char arg1[] = "foo";
    res = tpm2_attr_util_obj_strtoattr(arg1, &objattrs);
    assert_false(res);
}

static void test_tpm2_attr_util_obj_from_optarg_good(void **state) {
    (void) state;

    TPMA_OBJECT objattrs = 0;
    bool res = tpm2_attr_util_obj_from_optarg("0x00000002", &objattrs);
    assert_true(res);
    assert_int_equal(0x02, objattrs);

    objattrs = 0;
    char buf[] = "fixedtpm";
    res = tpm2_attr_util_obj_from_optarg(buf, &objattrs);
    assert_true(res);
    assert_int_equal(TPMA_OBJECT_FIXEDTPM, objattrs);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
            /* TPMA_NV Tests */
            test_nv_strtoattr_get(TPMA_NV_AUTHREAD),
            test_nv_strtoattr_get(TPMA_NV_AUTHWRITE),
            test_nv_strtoattr_get(TPMA_NV_CLEAR_STCLEAR),
            test_nv_strtoattr_get(TPMA_NV_GLOBALLOCK),
            test_nv_strtoattr_get(TPMA_NV_NO_DA),
            test_nv_strtoattr_get(TPMA_NV_ORDERLY),
            test_nv_strtoattr_get(TPMA_NV_OWNERREAD),
            test_nv_strtoattr_get(TPMA_NV_OWNERWRITE),
            test_nv_strtoattr_get(TPMA_NV_PLATFORMCREATE),
            test_nv_strtoattr_get(TPMA_NV_POLICYREAD),
            test_nv_strtoattr_get(TPMA_NV_POLICYWRITE),
            test_nv_strtoattr_get(TPMA_NV_POLICY_DELETE),
            test_nv_strtoattr_get(TPMA_NV_PPREAD),
            test_nv_strtoattr_get(TPMA_NV_PPWRITE),
            test_nv_strtoattr_get(TPMA_NV_READLOCKED),
            test_nv_strtoattr_get(TPMA_NV_READ_STCLEAR),
            test_nv_strtoattr_get(TPMA_NV_WRITEALL),
            test_nv_strtoattr_get(TPMA_NV_WRITEDEFINE),
            test_nv_strtoattr_get(TPMA_NV_WRITELOCKED),
            test_nv_strtoattr_get(TPMA_NV_WRITE_STCLEAR),
            test_nv_strtoattr_get(TPMA_NV_WRITTEN),
            cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_nt_good),
            cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_nt_bad),
            cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_nt_malformed),
            cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_multiple_good),
            cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_option_no_option),
            cmocka_unit_test(test_tpm2_attr_util_nv_strtoattr_token_unknown),
            test_nv_attrtostr_get(TPMA_NV_PPWRITE),
            test_nv_attrtostr_get(TPMA_NV_OWNERWRITE),
            test_nv_attrtostr_get(TPMA_NV_AUTHWRITE),
            test_nv_attrtostr_get(TPMA_NV_POLICYWRITE),
            test_nv_attrtostr_get(TPMA_NV_POLICY_DELETE),
            test_nv_attrtostr_get(TPMA_NV_WRITELOCKED),
            test_nv_attrtostr_get(TPMA_NV_WRITEALL),
            test_nv_attrtostr_get(TPMA_NV_WRITEDEFINE),
            test_nv_attrtostr_get(TPMA_NV_WRITE_STCLEAR),
            test_nv_attrtostr_get(TPMA_NV_GLOBALLOCK),
            test_nv_attrtostr_get(TPMA_NV_PPREAD),
            test_nv_attrtostr_get(TPMA_NV_OWNERREAD),
            test_nv_attrtostr_get(TPMA_NV_AUTHREAD),
            test_nv_attrtostr_get(TPMA_NV_POLICYREAD),
            test_nv_attrtostr_get(TPMA_NV_NO_DA),
            test_nv_attrtostr_get(TPMA_NV_ORDERLY),
            test_nv_attrtostr_get(TPMA_NV_CLEAR_STCLEAR),
            test_nv_attrtostr_get(TPMA_NV_READLOCKED),
            test_nv_attrtostr_get(TPMA_NV_WRITTEN),
            test_nv_attrtostr_get(TPMA_NV_PLATFORMCREATE),
            test_nv_attrtostr_get(TPMA_NV_READ_STCLEAR),
            test_nv_attrtostr_get(0),
            test_nv_attrtostr_get(0xFFFFFFFF),
            test_nv_attrtostr_get(0x100),     // bit 8 - reserved
            test_nv_attrtostr_get(0x200),     // bit 9 - reserved
            test_nv_attrtostr_get(0x100000),  //bit 20 - reserved
            test_nv_attrtostr_get(0x200000),  //bit 21 - reserved
            test_nv_attrtostr_get(0x400000),  //bit 22 - reserved
            test_nv_attrtostr_get(0x800000),  //bit 23- reserved
            test_nv_attrtostr_get(0x1000000), //bit 24- reserved
            test_nv_attrtostr_get(0x30), //nt=0x3
            test_nv_attrtostr_get(0x90), //nt=0x9
            test_nv_attrtostr_get(stclear_ppwrite),
            test_nv_attrtostr_get(stclear_ppwrite_0x30),
            test_nv_attrtostr_get(platformcreate_ownerread_nt_0x90_0x20000),
            /* TPMA_OBJECT Tests */

            /* From String to Attribute value */
            test_obj_strtoattr_get(TPMA_OBJECT_FIXEDTPM),
            test_obj_strtoattr_get(TPMA_OBJECT_STCLEAR),
            test_obj_strtoattr_get(TPMA_OBJECT_FIXEDPARENT),
            test_obj_strtoattr_get(TPMA_OBJECT_SENSITIVEDATAORIGIN),
            test_obj_strtoattr_get(TPMA_OBJECT_USERWITHAUTH),
            test_obj_strtoattr_get(TPMA_OBJECT_ADMINWITHPOLICY),
            test_obj_strtoattr_get(TPMA_OBJECT_NODA),
            test_obj_strtoattr_get(TPMA_OBJECT_ENCRYPTEDDUPLICATION),
            test_obj_strtoattr_get(TPMA_OBJECT_RESTRICTED),
            test_obj_strtoattr_get(TPMA_OBJECT_DECRYPT),
            test_obj_strtoattr_get(TPMA_OBJECT_ADMINWITHPOLICY),
            test_obj_strtoattr_get(TPMA_OBJECT_SIGN_ENCRYPT),

            /* From attribute to string value */
            test_obj_attrtostr_get(0xFFFFFFFF),
            test_obj_attrtostr_get(TPMA_OBJECT_FIXEDTPM),
            test_obj_attrtostr_get(TPMA_OBJECT_STCLEAR),
            test_obj_attrtostr_get(TPMA_OBJECT_FIXEDPARENT),
            test_obj_attrtostr_get(TPMA_OBJECT_SENSITIVEDATAORIGIN),
            test_obj_attrtostr_get(TPMA_OBJECT_USERWITHAUTH),
            test_obj_attrtostr_get(TPMA_OBJECT_ADMINWITHPOLICY),
            test_obj_attrtostr_get(TPMA_OBJECT_NODA),
            test_obj_attrtostr_get(TPMA_OBJECT_ENCRYPTEDDUPLICATION),
            test_obj_attrtostr_get(TPMA_OBJECT_RESTRICTED),
            test_obj_attrtostr_get(TPMA_OBJECT_DECRYPT),
            test_obj_attrtostr_get(TPMA_OBJECT_SIGN_ENCRYPT),
            test_obj_attrtostr_get(TPMA_OBJECT_RESERVED1_MASK),
            test_obj_attrtostr_get(TPMA_OBJECT_RESERVED2_MASK),
            test_obj_attrtostr_get(TPMA_OBJECT_RESERVED3_MASK),
            test_obj_attrtostr_get(TPMA_OBJECT_RESERVED4_MASK),
            test_obj_attrtostr_get(TPMA_OBJECT_RESERVED5_MASK),

            /* compound good */
            cmocka_unit_test(test_tpm2_attr_util_obj_strtoattr_multiple_good),

            /* negative tests */
            cmocka_unit_test(test_tpm2_attr_util_obj_strtoattr_token_unknown),

            /* test from an optarg */
            cmocka_unit_test(test_tpm2_attr_util_obj_from_optarg_good)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
