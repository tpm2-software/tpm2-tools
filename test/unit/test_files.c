/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "files.h"

typedef struct test_file test_file;
struct test_file {
    char *path;
    FILE *file;
};

static test_file *test_file_new(void) {

    test_file *tf = malloc(sizeof(test_file));
    if (!tf) {
        return NULL;
    }

    tf->path = strdup("xxx_test_files_xxx.test");
    if (!tf->path) {
        free(tf);
        return NULL;
    }

    tf->file = fopen(tf->path, "w+b");
    if (!tf->file) {
        free(tf->path);
        free(tf);
        return NULL;
    }

    return tf;
}

static void test_file_free(test_file *tf) {

    assert_non_null(tf);

    int rc = remove(tf->path);
    assert_return_code(rc, errno);

    free(tf->path);
    fclose(tf->file);
    free(tf);
}

static int test_setup(void **state) {

    test_file *tf = test_file_new();
    assert_non_null(tf);
    *state = tf;
    return 0;
}

static int test_teardown(void **state) {

    test_file *tf = (test_file *) *state;
    test_file_free(tf);
    return 0;
}

static test_file *test_file_from_state(void **state) {

    test_file *f = (test_file *) *state;
    assert_non_null(f);
    return f;
}

#define READ_WRITE_TEST(size, expected) \
	static void test_file_read_write_##size(void **state) { \
    \
        FILE *f = test_file_from_state(state)->file; \
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

    FILE *f = test_file_from_state(state)->file;

    UINT8 expected[1024];
    memset(expected, 0xBB, sizeof(expected));

    bool res = files_write_bytes(f, expected, sizeof(expected));
    assert_true(res);

    rewind(f);

    UINT8 found[1024] = { 0 };
    res = files_read_bytes(f, found, sizeof(found));
    assert_true(res);

    assert_memory_equal(expected, found, sizeof(found));
}

static void test_file_read_write_0_bytes(void **state) {

    FILE *f = test_file_from_state(state)->file;

    UINT8 data[1];
    bool res = files_write_bytes(f, data, 0);
    assert_true(res);

    res = files_read_bytes(f, data, 0);
    assert_true(res);
}

static void test_file_read_write_header(void **state) {

    FILE *f = test_file_from_state(state)->file;

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
        FILE *f = test_file_from_state(state)->file; \
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

    FILE *f = test_file_from_state(state)->file;

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

static void test_file_size(void **state) {

    test_file *tf = test_file_from_state(state);

    UINT8 data[128] = { 0 };

    bool res = files_write_bytes(tf->file, data, sizeof(data));
    assert_true(res);

    int rc = fflush(tf->file);
    assert_return_code(rc, errno);

    unsigned long file_size;
    res = files_get_file_size_path(tf->path, &file_size);
    assert_true(res);

    assert_int_equal(file_size, sizeof(data));
}

static void test_file_size_bad_args(void **state) {

    unsigned long file_size;
    bool res = files_get_file_size_path("this_should_be_a_bad_path",
            &file_size);
    assert_false(res);

    res = files_get_file_size_path(NULL, &file_size);
    assert_false(res);

    test_file *tf = test_file_from_state(state);

    res = files_get_file_size_path(tf->path, NULL);
    assert_false(res);
}

static void test_file_exists(void **state) {

    test_file *tf = test_file_from_state(state);

    bool res = files_does_file_exist(tf->path);
    assert_true(res);
}

static void test_file_exists_bad_args(void **state) {

    (void) state;

    bool res = files_does_file_exist("this_should_be_a_bad_path");
    assert_false(res);

    res = files_does_file_exist(NULL);
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

        cmocka_unit_test_setup_teardown(test_file_size,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_size_bad_args,
                test_setup, test_teardown),

        cmocka_unit_test_setup_teardown(test_file_exists,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_file_exists_bad_args,
                test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
