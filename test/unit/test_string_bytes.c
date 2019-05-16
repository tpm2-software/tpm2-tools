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

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "tpm2_util.h"

static void test_is_big_endian(void **state) {

    uint16_t test = 0xFF00;
    uint8_t *b = (uint8_t *)&test;
    (void)state;

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
    (void)argc;
    (void)argv;

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
