//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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

#include "tpm2_password_util.h"

static void test_tpm2_password_util_from_optarg_raw_noprefix(void **state) {
    (void)state;

    TPM2B_AUTH dest;
    bool res = tpm2_password_util_from_optarg("abcd", &dest);
    assert_true(res);
    assert_int_equal(dest.size, 4);
    assert_memory_equal(dest.buffer, "abcd", 4);
}

static void test_tpm2_password_util_from_optarg_str_prefix(void **state) {
    (void)state;

    TPM2B_AUTH dest;
    bool res = tpm2_password_util_from_optarg("str:abcd", &dest);
    assert_true(res);
    assert_int_equal(dest.size, 4);
    assert_memory_equal(dest.buffer, "abcd", 4);
}

static void test_tpm2_password_util_from_optarg_hex_prefix(void **state) {
    (void)state;

    TPM2B_AUTH dest;
    BYTE expected[] = {
            0x12, 0x34, 0xab, 0xcd
    };

    bool res = tpm2_password_util_from_optarg("hex:1234abcd", &dest);
    assert_true(res);
    assert_int_equal(dest.size, sizeof(expected));
    assert_memory_equal(dest.buffer, expected, sizeof(expected));
}

static void test_tpm2_password_util_from_optarg_str_escaped_hex_prefix(void **state) {
    (void)state;

    TPM2B_AUTH dest;

    bool res = tpm2_password_util_from_optarg("str:hex:1234abcd", &dest);
    assert_true(res);
    assert_int_equal(dest.size, 12);
    assert_memory_equal(dest.buffer, "hex:1234abcd", 12);
}

static void test_tpm2_password_util_from_optarg_raw_overlength(void **state) {
    (void)state;

    TPM2B_AUTH dest;
    char *overlength = "this_password_is_over_64_characters_in_length_and_should_fail_XXX";
    bool res = tpm2_password_util_from_optarg(overlength, &dest);
    assert_false(res);
}

static void test_tpm2_password_util_from_optarg_hex_overlength(void **state) {
    (void)state;

    TPM2B_AUTH dest;
    /* 65 hex chars generated via: echo \"`xxd -p -c256 -l65 /dev/urandom`\"\; */
    char *overlength =
        "ae6f6fa01589aa7b227bb6a34c7a8e0c273adbcf14195ce12391a5cc12a5c271f62088"
        "dbfcf1914fdf120da183ec3ad6cc78a2ffd91db40a560169961e3a6d26bf";
    bool res = tpm2_password_util_from_optarg(overlength, &dest);
    assert_false(res);
}

static void test_tpm2_password_util_from_optarg_empty_str(void **state) {
    (void)state;

    TPM2B_AUTH dest = {
        .size = 42
    };

    bool res = tpm2_password_util_from_optarg("", &dest);
    assert_true(res);
    assert_int_equal(dest.size, 0);
}

static void test_tpm2_password_util_from_optarg_empty_str_str_prefix(void **state) {
    (void)state;

    TPM2B_AUTH dest = {
        .size = 42
    };

    bool res = tpm2_password_util_from_optarg("str:", &dest);
    assert_true(res);
    assert_int_equal(dest.size, 0);
}


static void test_tpm2_password_util_from_optarg_empty_str_hex_prefix(void **state) {
    (void)state;

    TPM2B_AUTH dest = {
        .size = 42
    };

    bool res = tpm2_password_util_from_optarg("hex:", &dest);
    assert_true(res);
    assert_int_equal(dest.size, 0);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_tpm2_password_util_from_optarg_raw_noprefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_str_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_hex_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_str_escaped_hex_prefix),

            /* negative testing */
            cmocka_unit_test(test_tpm2_password_util_from_optarg_raw_overlength),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_hex_overlength),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str_str_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str_hex_prefix)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
