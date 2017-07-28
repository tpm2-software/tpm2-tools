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

#include "tpm2_nv_util.h"

#define single_test_get(set) \
    cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_##set)

#define single_item_test(argstr, set) \
    static void test_tpm2_nv_util_attrs_to_val_##set(void **state) { \
        \
        (void)state; \
    \
        TPMA_NV nvattrs = { \
            .val = 0, \
        }; \
        /* make mutable strings for strtok_r */ \
        char arg[] = argstr; \
        bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs); \
        assert_true(res); \
        assert_true(nvattrs.set); \
        assert_true(nvattrs.val == TPMA_NV_##set); \
    }

single_item_test("authread", TPMA_NV_AUTHREAD);
single_item_test("authwrite", TPMA_NV_AUTHWRITE);
single_item_test("clear_stclear", TPMA_NV_CLEAR_STCLEAR);
single_item_test("globallock", TPMA_NV_GLOBALLOCK);
single_item_test("no_da", TPMA_NV_NO_DA);
single_item_test("orderly", TPMA_NV_ORDERLY);
single_item_test("ownerread", TPMA_NV_OWNERREAD);
single_item_test("ownerwrite", TPMA_NV_OWNERWRITE);
single_item_test("platformcreate", TPMA_NV_PLATFORMCREATE);
single_item_test("policyread", TPMA_NV_POLICYREAD);
single_item_test("policywrite", TPMA_NV_POLICYWRITE);
single_item_test("policydelete", TPMA_NV_POLICY_DELETE);
single_item_test("ppread", TPMA_NV_PPREAD);
single_item_test("ppwrite", TPMA_NV_PPWRITE);
single_item_test("readlocked", TPMA_NV_READLOCKED);
single_item_test("read_stclear", TPMA_NV_READ_STCLEAR);
single_item_test("writeall", TPMA_NV_WRITEALL);
single_item_test("writedefine", TPMA_NV_WRITEDEFINE);
single_item_test("writelocked", TPMA_NV_WRITELOCKED);
single_item_test("write_stclear", TPMA_NV_WRITE_STCLEAR);
single_item_test("written", TPMA_NV_WRITTEN);

static void test_tpm2_nv_util_attrs_to_val_nt_good(void **state) {
    (void) state;

    TPMA_NV nvattrs = { .val = 0, };

    char arg[] = "nt=0x1";
    bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs);
    assert_true(res);
    assert_true(nvattrs.TPM_NT == 0x1);
}

static void test_tpm2_nv_util_attrs_to_val_nt_bad(void **state) {
    (void) state;

    TPMA_NV nvattrs = { .val = 0, };

    char arg[] = "nt=16";
    bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs);
    assert_false(res);
}

static void test_tpm2_nv_util_attrs_to_val_nt_malformed(void **state) {
    (void) state;

    TPMA_NV nvattrs = { .val = 0, };

    char arg[] = "nt=";
    bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs);
    assert_false(res);

    char arg1[] = "nt";
    res = tpm2_nv_util_attrs_to_val(arg1, &nvattrs);
    assert_false(res);
}

static void test_tpm2_nv_util_attrs_to_val_option_no_option(void **state) {
    (void) state;

    TPMA_NV nvattrs = { .val = 0, };

    char arg[] = "authread=";
    bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs);
    assert_false(res);

    char arg1[] = "authread=0x1";
    res = tpm2_nv_util_attrs_to_val(arg1, &nvattrs);
    assert_false(res);
}

static void test_tpm2_nv_util_attrs_to_val_multiple_good(void **state) {
    (void) state;

    TPMA_NV nvattrs = { .val = 0, };

    char arg[] = "authread|authwrite|nt=0x4";
    bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs);
    assert_true(res);
    assert_true(nvattrs.TPM_NT == 0x4);
    assert_true(nvattrs.TPMA_NV_AUTHREAD);
    assert_true(nvattrs.TPMA_NV_AUTHWRITE);
}

static void test_tpm2_nv_util_attrs_to_val_token_unknown(void **state) {
    (void) state;

    TPMA_NV nvattrs = { .val = 0, };

    char arg[] = "authread|authfoo|nt=0x4";
    bool res = tpm2_nv_util_attrs_to_val(arg, &nvattrs);
    assert_false(res);

    char arg1[] = "foo";
    res = tpm2_nv_util_attrs_to_val(arg1, &nvattrs);
    assert_false(res);

    char arg2[] = "foo=";
    res = tpm2_nv_util_attrs_to_val(arg2, &nvattrs);
    assert_false(res);

    /* should be interprested as the whole thing, no = */
    char arg3[] = "nt:0x4";
    res = tpm2_nv_util_attrs_to_val(arg3, &nvattrs);
    assert_false(res);
}

#define test_attrtostr(value, expected) \
    static void test_tpm2_nv_util_attrtostr_##value(void **state) { \
    \
        (void) state; \
    \
        TPMA_NV attrs = { .val = value }; \
        char *str = tpm2_nv_util_attrtostr(attrs); \
        assert_string_equal(str, expected); \
    \
        free(str); \
    }

#define test_attrtostr_get(value) \
		cmocka_unit_test(test_tpm2_nv_util_attrtostr_##value)

test_attrtostr(0, "<none>");
test_attrtostr(TPMA_NV_TPMA_NV_PPWRITE, "ppwrite")
test_attrtostr(TPMA_NV_TPMA_NV_OWNERWRITE, "ownerwrite")
test_attrtostr(TPMA_NV_TPMA_NV_AUTHWRITE, "authwrite")
test_attrtostr(TPMA_NV_TPMA_NV_POLICYWRITE, "policywrite")
test_attrtostr(TPMA_NV_TPMA_NV_POLICY_DELETE, "policydelete")
test_attrtostr(TPMA_NV_TPMA_NV_WRITELOCKED, "writelocked")
test_attrtostr(TPMA_NV_TPMA_NV_WRITEALL, "writeall")
test_attrtostr(TPMA_NV_TPMA_NV_WRITEDEFINE, "writedefine")
test_attrtostr(TPMA_NV_TPMA_NV_WRITE_STCLEAR, "write_stclear")
test_attrtostr(TPMA_NV_TPMA_NV_GLOBALLOCK, "globallock")
test_attrtostr(TPMA_NV_TPMA_NV_PPREAD, "ppread")
test_attrtostr(TPMA_NV_TPMA_NV_OWNERREAD, "ownerread")
test_attrtostr(TPMA_NV_TPMA_NV_AUTHREAD, "authread")
test_attrtostr(TPMA_NV_TPMA_NV_POLICYREAD, "policyread")
test_attrtostr(TPMA_NV_TPMA_NV_NO_DA, "no_da")
test_attrtostr(TPMA_NV_TPMA_NV_ORDERLY, "orderly")
test_attrtostr(TPMA_NV_TPMA_NV_CLEAR_STCLEAR, "clear_stclear")
test_attrtostr(TPMA_NV_TPMA_NV_READLOCKED, "readlocked")
test_attrtostr(TPMA_NV_TPMA_NV_WRITTEN, "written")
test_attrtostr(TPMA_NV_TPMA_NV_PLATFORMCREATE, "platformcreate")
test_attrtostr(TPMA_NV_TPMA_NV_READ_STCLEAR, "read_stclear")

test_attrtostr(0x100, "<reserved(8)>") //bit 8 - reserved
test_attrtostr(0x200, "<reserved(9)>") //bit 9 - reserved

test_attrtostr(0x100000, "<reserved(20)>")  //bit 20 - reserved
test_attrtostr(0x200000, "<reserved(21)>")  //bit 21 - reserved
test_attrtostr(0x400000, "<reserved(22)>")  //bit 22 - reserved
test_attrtostr(0x800000, "<reserved(23)>")  //bit 23- reserved
test_attrtostr(0x1000000, "<reserved(24)>") //bit 24- reserved

test_attrtostr(0x30, "nt=0x3") //bit 24- reserved
test_attrtostr(0x90, "nt=0x9") //bit 24- reserved

#define ALL_FIELDS \
        "ppwrite|ownerwrite|authwrite|policywrite|nt=0xF|<reserved(8)>"  \
        "|<reserved(9)>|policydelete|writelocked|writeall|writedefine"   \
        "|write_stclear|globallock|ppread|ownerread|authread|policyread" \
        "|<reserved(20)>|<reserved(21)>|<reserved(22)>|<reserved(23)>"   \
        "|<reserved(24)>|no_da|orderly|clear_stclear|readlocked|written" \
        "|platformcreate|read_stclear"

test_attrtostr(0xFFFFFFFF, ALL_FIELDS);

#define test_attrtostr_compound(id, value, expected) \
    static void test_tpm2_nv_util_attrtostr_##id(void **state) { \
    \
        (void) state; \
    \
        TPMA_NV attrs = { .val = value }; \
        char *str = tpm2_nv_util_attrtostr(attrs); \
        assert_string_equal(str, expected); \
    \
        free(str); \
    }

test_attrtostr_compound(stclear_ppwrite,
        TPMA_NV_TPMA_NV_WRITE_STCLEAR|TPMA_NV_TPMA_NV_PPWRITE,
        "ppwrite|write_stclear")
test_attrtostr_compound(stclear_ppwrite_0x30,
        TPMA_NV_TPMA_NV_WRITE_STCLEAR|TPMA_NV_TPMA_NV_PPWRITE|0x30,
        "ppwrite|nt=0x3|write_stclear")
test_attrtostr_compound(platformcreate_owneread_nt_0x90_0x20000,
        TPMA_NV_TPMA_NV_PLATFORMCREATE|TPMA_NV_TPMA_NV_AUTHWRITE|0x90|0x200000,
        "authwrite|nt=0x9|<reserved(21)>|platformcreate")

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
            single_test_get(TPMA_NV_AUTHREAD),
            single_test_get(TPMA_NV_AUTHWRITE),
            single_test_get(TPMA_NV_CLEAR_STCLEAR),
            single_test_get(TPMA_NV_GLOBALLOCK),
            single_test_get(TPMA_NV_NO_DA),
            single_test_get(TPMA_NV_ORDERLY),
            single_test_get(TPMA_NV_OWNERREAD),
            single_test_get(TPMA_NV_OWNERWRITE),
            single_test_get(TPMA_NV_PLATFORMCREATE),
            single_test_get(TPMA_NV_POLICYREAD),
            single_test_get(TPMA_NV_POLICYWRITE),
            single_test_get(TPMA_NV_POLICY_DELETE),
            single_test_get(TPMA_NV_PPREAD),
            single_test_get(TPMA_NV_PPWRITE),
            single_test_get(TPMA_NV_READLOCKED),
            single_test_get(TPMA_NV_READ_STCLEAR),
            single_test_get(TPMA_NV_WRITEALL),
            single_test_get(TPMA_NV_WRITEDEFINE),
            single_test_get(TPMA_NV_WRITELOCKED),
            single_test_get(TPMA_NV_WRITE_STCLEAR),
            single_test_get(TPMA_NV_WRITTEN),
            cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_nt_good),
            cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_nt_bad),
            cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_nt_malformed),
            cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_multiple_good),
            cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_option_no_option),
            cmocka_unit_test(test_tpm2_nv_util_attrs_to_val_token_unknown),
            test_attrtostr_get(TPMA_NV_TPMA_NV_PPWRITE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_OWNERWRITE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_AUTHWRITE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_POLICYWRITE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_POLICY_DELETE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_WRITELOCKED),
            test_attrtostr_get(TPMA_NV_TPMA_NV_WRITEALL),
            test_attrtostr_get(TPMA_NV_TPMA_NV_WRITEDEFINE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_WRITE_STCLEAR),
            test_attrtostr_get(TPMA_NV_TPMA_NV_GLOBALLOCK),
            test_attrtostr_get(TPMA_NV_TPMA_NV_PPREAD),
            test_attrtostr_get(TPMA_NV_TPMA_NV_OWNERREAD),
            test_attrtostr_get(TPMA_NV_TPMA_NV_AUTHREAD),
            test_attrtostr_get(TPMA_NV_TPMA_NV_POLICYREAD),
            test_attrtostr_get(TPMA_NV_TPMA_NV_NO_DA),
            test_attrtostr_get(TPMA_NV_TPMA_NV_ORDERLY),
            test_attrtostr_get(TPMA_NV_TPMA_NV_CLEAR_STCLEAR),
            test_attrtostr_get(TPMA_NV_TPMA_NV_READLOCKED),
            test_attrtostr_get(TPMA_NV_TPMA_NV_WRITTEN),
            test_attrtostr_get(TPMA_NV_TPMA_NV_PLATFORMCREATE),
            test_attrtostr_get(TPMA_NV_TPMA_NV_READ_STCLEAR),
            test_attrtostr_get(0),
            test_attrtostr_get(0xFFFFFFFF),
            test_attrtostr_get(0x100),     // bit 8 - reserved
            test_attrtostr_get(0x200),     // bit 9 - reserved
            test_attrtostr_get(0x100000),  //bit 20 - reserved
            test_attrtostr_get(0x200000),  //bit 21 - reserved
            test_attrtostr_get(0x400000),  //bit 22 - reserved
            test_attrtostr_get(0x800000),  //bit 23- reserved
            test_attrtostr_get(0x1000000), //bit 24- reserved
            test_attrtostr_get(0x30), //nt=0x3
            test_attrtostr_get(0x90), //nt=0x9
            test_attrtostr_get(stclear_ppwrite),
            test_attrtostr_get(stclear_ppwrite_0x30),
            test_attrtostr_get(platformcreate_owneread_nt_0x90_0x20000)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
