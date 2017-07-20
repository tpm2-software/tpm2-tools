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

/*
 assert_true(nvattrs.x); \
    \
        assert_true(nvattrs.val = TPMA_NV_##x); \
*/

#define single_test_get(set) \
    test_tpm2_nv_util_attrs_to_val_##set

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

//        dispatch_arg_add(nt),

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = { cmocka_unit_test(
            single_test_get(TPMA_NV_AUTHREAD)), cmocka_unit_test(
            single_test_get(TPMA_NV_AUTHWRITE)), cmocka_unit_test(
            single_test_get(TPMA_NV_CLEAR_STCLEAR)), cmocka_unit_test(
            single_test_get(TPMA_NV_GLOBALLOCK)), cmocka_unit_test(
            single_test_get(TPMA_NV_NO_DA)), cmocka_unit_test(
            single_test_get(TPMA_NV_ORDERLY)), cmocka_unit_test(
            single_test_get(TPMA_NV_OWNERREAD)), cmocka_unit_test(
            single_test_get(TPMA_NV_OWNERWRITE)), cmocka_unit_test(
            single_test_get(TPMA_NV_PLATFORMCREATE)), cmocka_unit_test(
            single_test_get(TPMA_NV_POLICYREAD)), cmocka_unit_test(
            single_test_get(TPMA_NV_POLICYWRITE)), cmocka_unit_test(
            single_test_get(TPMA_NV_POLICY_DELETE)), cmocka_unit_test(
            single_test_get(TPMA_NV_PPREAD)), cmocka_unit_test(
            single_test_get(TPMA_NV_PPWRITE)), cmocka_unit_test(
            single_test_get(TPMA_NV_READLOCKED)), cmocka_unit_test(
            single_test_get(TPMA_NV_READ_STCLEAR)), cmocka_unit_test(
            single_test_get(TPMA_NV_WRITEALL)), cmocka_unit_test(
            single_test_get(TPMA_NV_WRITEDEFINE)), cmocka_unit_test(
            single_test_get(TPMA_NV_WRITELOCKED)), cmocka_unit_test(
            single_test_get(TPMA_NV_WRITE_STCLEAR)), cmocka_unit_test(
            single_test_get(TPMA_NV_WRITTEN)), cmocka_unit_test(
            test_tpm2_nv_util_attrs_to_val_nt_good), cmocka_unit_test(
            test_tpm2_nv_util_attrs_to_val_nt_bad), cmocka_unit_test(
            test_tpm2_nv_util_attrs_to_val_nt_malformed), cmocka_unit_test(
            test_tpm2_nv_util_attrs_to_val_multiple_good), cmocka_unit_test(
            test_tpm2_nv_util_attrs_to_val_option_no_option), cmocka_unit_test(
            test_tpm2_nv_util_attrs_to_val_token_unknown), };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
