//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "tpm2_hierarchy.h"
#include "tpm2_util.h"

static void test_tpm2_hierarchy_from_optarg_NULL(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg(NULL, &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_false(result);
}

static void test_tpm2_hierarchy_from_optarg_empty(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg("", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_false(result);
}

static void test_tpm2_hierarchy_from_optarg_invalid_id(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg("q", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_false(result);
}

static void test_tpm2_hierarchy_from_optarg_invalid_str(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg("nope", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_false(result);
}

static void test_tpm2_hierarchy_from_optarg_valid_ids(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg("o", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_OWNER);

    result = tpm2_hierarchy_from_optarg("p", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_PLATFORM);

    result = tpm2_hierarchy_from_optarg("e", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_ENDORSEMENT);

    result = tpm2_hierarchy_from_optarg("n", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_NULL);

    result = tpm2_hierarchy_from_optarg("0xBADC0DE", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_true(result);
    assert_int_equal(h, 0xBADC0DE);
}

static void test_tpm2_hierarchy_from_optarg_valid_ids_disabled(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg("o", &h,
            TPM2_HIERARCHY_FLAGS_N);
    assert_false(result);

    result = tpm2_hierarchy_from_optarg("p", &h,
            TPM2_HIERARCHY_FLAGS_O);
    assert_false(result);

    result = tpm2_hierarchy_from_optarg("e", &h,
            TPM2_HIERARCHY_FLAGS_P);
    assert_false(result);

    result = tpm2_hierarchy_from_optarg("n", &h,
            TPM2_HIERARCHY_FLAGS_E);
    assert_false(result);

    result = tpm2_hierarchy_from_optarg("0xBADC0DE", &h,
            TPM2_HIERARCHY_FLAGS_NONE);
    assert_true(result);
    assert_int_equal(h, 0xBADC0DE);
}

static void test_tpm2_hierarchy_from_optarg_valid_ids_enabled(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_hierarchy_from_optarg("o", &h,
            TPM2_HIERARCHY_FLAGS_O);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_OWNER);

    result = tpm2_hierarchy_from_optarg("p", &h,
            TPM2_HIERARCHY_FLAGS_P);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_PLATFORM);

    result = tpm2_hierarchy_from_optarg("e", &h,
            TPM2_HIERARCHY_FLAGS_E);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_ENDORSEMENT);

    result = tpm2_hierarchy_from_optarg("n", &h,
            TPM2_HIERARCHY_FLAGS_N);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_NULL);

    result = tpm2_hierarchy_from_optarg("0xBADC0DE", &h,
            TPM2_HIERARCHY_FLAGS_ALL);
    assert_true(result);
    assert_int_equal(h, 0xBADC0DE);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_NULL),
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_empty),
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_invalid_id),
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_invalid_str),
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_valid_ids),
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_valid_ids_disabled),
        cmocka_unit_test(test_tpm2_hierarchy_from_optarg_valid_ids_enabled),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
