/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_hierarchy.h"
#include "tpm2_util.h"

static void test_tpm2_util_handle_from_optarg_NULL(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg(NULL, &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_false(result);
}

static void test_tpm2_util_handle_from_optarg_empty(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg("", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_false(result);
}

static void test_tpm2_util_handle_from_optarg_invalid_id(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg("q", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_false(result);
}

static void test_tpm2_util_handle_from_optarg_invalid_str(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg("nope", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_false(result);
}

static void test_tpm2_util_handle_from_optarg_valid_ids(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg("o", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_OWNER);

    result = tpm2_util_handle_from_optarg("p", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_PLATFORM);

    result = tpm2_util_handle_from_optarg("e", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_ENDORSEMENT);

    result = tpm2_util_handle_from_optarg("n", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_NULL);

    result = tpm2_util_handle_from_optarg("0x81010009", &h,
            TPM2_HANDLE_ALL_W_NV);
    assert_true(result);
    assert_int_equal(h, 0x81010009);
}

static void test_tpm2_util_handle_from_optarg_valid_ids_disabled(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg("o", &h, TPM2_HANDLE_FLAGS_N);
    assert_false(result);

    result = tpm2_util_handle_from_optarg("p", &h, TPM2_HANDLE_FLAGS_O);
    assert_false(result);

    result = tpm2_util_handle_from_optarg("e", &h, TPM2_HANDLE_FLAGS_P);
    assert_false(result);

    result = tpm2_util_handle_from_optarg("n", &h, TPM2_HANDLE_FLAGS_E);
    assert_false(result);

    result = tpm2_util_handle_from_optarg("0x81010009", &h,
            TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    assert_false(result);
}

static void test_tpm2_util_handle_from_optarg_valid_ids_enabled(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    bool result = tpm2_util_handle_from_optarg("o", &h, TPM2_HANDLE_FLAGS_O);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_OWNER);

    result = tpm2_util_handle_from_optarg("p", &h, TPM2_HANDLE_FLAGS_P);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_PLATFORM);

    result = tpm2_util_handle_from_optarg("e", &h, TPM2_HANDLE_FLAGS_E);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_ENDORSEMENT);

    result = tpm2_util_handle_from_optarg("n", &h, TPM2_HANDLE_FLAGS_N);
    assert_true(result);
    assert_int_equal(h, TPM2_RH_NULL);
}

static void test_tpm2_util_handle_from_optarg_nv_valid_range(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    /*
     * NV index specified as NV:offset
     */
    bool result = tpm2_util_handle_from_optarg("1", &h, TPM2_HANDLE_FLAGS_NV);
    assert_true(result);
    assert_int_equal(h, 0x01000001);

    /*
     * NV index specified as full raw handle
     */
    result = tpm2_util_handle_from_optarg("0x01000002", &h,
            TPM2_HANDLE_FLAGS_NV);
    assert_true(result);
    assert_int_equal(h, 0x01000002);
}

static void test_tpm2_util_handle_from_optarg_nv_invalid_offset(void **state) {
    UNUSED(state);

    TPMI_RH_PROVISION h;
    /*
     * No offset specified
     */
    bool result = tpm2_util_handle_from_optarg("", &h, TPM2_HANDLE_FLAGS_NV);
    assert_false(result);

    /*
     * Offset is non hex string
     */
    result = tpm2_util_handle_from_optarg("random", &h, TPM2_HANDLE_FLAGS_NV);
    assert_false(result);

    /*
     * Offset is larger than TPM2_HR_HANDLE_MASK
     */
    result = tpm2_util_handle_from_optarg("0x12345678", &h,
            TPM2_HANDLE_FLAGS_NV);
    assert_false(result);

    /*
     * Wrongly specify NV index as raw handle and disable NV in flags
     */
    result = tpm2_util_handle_from_optarg("0x01000001", &h,
            TPM2_HANDLE_FLAGS_O);
    assert_false(result);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_NULL),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_empty),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_invalid_id),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_invalid_str),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_valid_ids),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_valid_ids_disabled),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_valid_ids_enabled),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_nv_valid_range),
        cmocka_unit_test(test_tpm2_util_handle_from_optarg_nv_invalid_offset),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
