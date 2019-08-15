/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_util.h"

static void test_is_big_endian(void **state) {

    uint16_t test = 0xFF00;
    uint8_t *b = (uint8_t *) &test;
    (void) state;

    bool test_host_is_big_endian = b[0] == 0xFF;
    bool host_is_big_endian = tpm2_util_is_big_endian();

    assert_true(test_host_is_big_endian == host_is_big_endian);
}

static void test_popcount(void **state) {

    (void) state;

    UINT32 count = tpm2_util_pop_count(0x4453E424);
    assert_int_equal(12, count);

    count = tpm2_util_pop_count(0);
    assert_int_equal(0, count);

    count = tpm2_util_pop_count(~0);
    assert_int_equal(32, count);
}

#define TEST_ENDIAN_CONVERT(size, value, expected) \
    static void test_convert_##size(void **state) { \
    \
        (void)state; \
        UINT##size test = tpm2_util_endian_swap_##size(value); \
        assert_int_equal(test, expected); \
    }

TEST_ENDIAN_CONVERT(16, 0xFF00, 0x00FF)
TEST_ENDIAN_CONVERT(32, 0xAABBCCDD, 0xDDCCBBAA)
TEST_ENDIAN_CONVERT(64, 0x0011223344556677, 0x7766554433221100)

#define TEST_ENDIAN_HTON(size, value, le_expected) \
    static void test_hton_##size(void **state) { \
    \
        (void)state; \
        UINT##size test = tpm2_util_hton_##size(value); \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        UINT##size expected = is_big_endian ? value : le_expected; \
        assert_int_equal(test, expected); \
        \
    }

TEST_ENDIAN_HTON(16, 0xFF00, 0x00FF)
TEST_ENDIAN_HTON(32, 0xAABBCCDD, 0xDDCCBBAA)
TEST_ENDIAN_HTON(64, 0x0011223344556677, 0x7766554433221100)

#define TEST_ENDIAN_NTOH(size, value, le_expected) \
    static void test_ntoh_##size(void **state) { \
    \
        (void)state; \
        UINT##size test = tpm2_util_ntoh_##size(value); \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        UINT##size expected = is_big_endian ? value : le_expected; \
        assert_int_equal(test, expected); \
        \
    }

TEST_ENDIAN_NTOH(16, 0xFF00, 0x00FF)
TEST_ENDIAN_NTOH(32, 0xAABBCCDD, 0xDDCCBBAA)
TEST_ENDIAN_NTOH(64, 0x0011223344556677, 0x7766554433221100)

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_big_endian),
        cmocka_unit_test(test_convert_16),
        cmocka_unit_test(test_convert_32),
        cmocka_unit_test(test_convert_64),
        cmocka_unit_test(test_hton_16),
        cmocka_unit_test(test_hton_32),
        cmocka_unit_test(test_hton_64),
        cmocka_unit_test(test_ntoh_16),
        cmocka_unit_test(test_ntoh_32),
        cmocka_unit_test(test_ntoh_64),
        cmocka_unit_test(test_popcount)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
