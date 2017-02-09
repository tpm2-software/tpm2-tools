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
#include <stdio.h>
#include <setjmp.h>

#include <cmocka.h>
#include <sapi/tpm20.h>

#include "files.h"

static int test_setup(void **state) {

    FILE *f = tmpfile();
    assert_non_null(f);
    *state = f;
    return 0;
}

static int test_teardown(void **state) {

    FILE *f = (FILE *)*state;
    assert_non_null(f);
    fclose(f);
    return 0;
}

static FILE *file_from_state(void **state) {

    FILE *f = (FILE *)*state;
    assert_non_null(f);
    return f;
}

#define READ_WRITE_TEST(size, expected) \
	static void test_file_read_write_##size(void **state) { \
    \
        FILE *f = file_from_state(state); \
    \
        bool res = files_write_##size(f, expected); \
        assert_true(res); \
    \
        rewind(f); \
    \
        UINT##size found; \
        res = files_read_##size(f, &found); \
        assert_true(res); \
    \
        assert_int_equal(found, expected); \
    }

READ_WRITE_TEST(16, 0xABCD)
READ_WRITE_TEST(32, 0x11223344)
READ_WRITE_TEST(64, 0x1122334455667788)

static void test_file_read_write_bytes(void **state) {

    FILE *f = file_from_state(state);

    UINT8 expected[1024];
    memset(expected, 0xBB, sizeof(expected));

    bool res = files_write_bytes(f, expected, sizeof(expected));
    assert_true(res);

    rewind(f);

    UINT8 found[1024] = { 0 };
    res = files_read_bytes(f, found, sizeof(found));

    assert_memory_equal(expected, found, sizeof(found));
}

static void test_file_read_write_0_bytes(void **state) {

    FILE *f = file_from_state(state);

    UINT8 data[1];
    bool res = files_write_bytes(f, data, 0);
    assert_true(res);

    res = files_read_bytes(f, data, 0);
    assert_true(res);
}

static void test_file_read_write_header(void **state) {

    FILE *f = file_from_state(state);

    UINT32 expected = 0xAABBCCDD;
    bool res = files_write_header(f, expected);
    assert_true(res);

    rewind(f);

    UINT32 found;
    res = files_read_header(f, &found);
    assert_true(res);

    assert_int_equal(expected, found);
}

#define READ_WRITE_TEST_BAD_PARAMS(size) \
    static void test_file_read_write_bad_params_##size(void **state) { \
    \
        UINT##size expected = 42; \
        FILE *f = file_from_state(state); \
        bool res = files_write_##size(NULL, expected); \
        assert_false(res); \
    \
        UINT##size found; \
        res = files_read_##size(NULL, &found); \
        assert_false(res); \
    \
        res = files_read_##size(f, NULL); \
        assert_false(res); \
    \
        res = files_read_##size(NULL, NULL); \
        assert_false(res); \
    }

READ_WRITE_TEST_BAD_PARAMS(16)
READ_WRITE_TEST_BAD_PARAMS(32)
READ_WRITE_TEST_BAD_PARAMS(64)

static void test_file_read_write_bad_params_bytes(void **state) {

    FILE *f = file_from_state(state);

    UINT8 data[1];
    bool res = files_write_bytes(f, NULL, sizeof(data));
    assert_false(res);

    res = files_write_bytes(NULL, data, sizeof(data));
    assert_false(res);

    res = files_read_bytes(f, NULL, sizeof(data));
    assert_false(res);

    res = files_read_bytes(NULL, data, sizeof(data));
    assert_false(res);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_file_read_write_16,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_32,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_64,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_bytes,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_0_bytes,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_header,
                        test_setup, test_teardown),

        cmocka_unit_test_setup_teardown(test_file_read_write_bad_params_16,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_bad_params_32,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_bad_params_64,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_read_write_bad_params_bytes,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
