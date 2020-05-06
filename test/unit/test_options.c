/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_options.h"
#include "tpm2_util.h"

typedef struct test_pair test_pair;
struct test_pair {
    union {
        const char *cn;
        void *v;
    } input[2];

    union {
        char *s;
        void *v;
        int i;
    } output;
};

static void set_getenv(const char *name, char *ret) {

    test_pair *e = calloc(1, sizeof(test_pair));
    assert_non_null(e);

    e->input[0].cn = name;
    e->output.s = ret;

    will_return(__wrap_tpm2_util_getenv, e);
}
#define HANDLE_SKIP_CHECK ((void *) -1)
char *__wrap_tpm2_util_getenv(const char *name) {

    test_pair *x = mock_ptr_type(test_pair *);

    const char *expected_name = x->input[0].cn;
    char *ret = x->output.s;
    free(x);

    assert_string_equal(name, expected_name);

    return ret;
}

TSS2_RC __wrap_Tss2_TctiLdr_Initialize(const char *nameConf,
        TSS2_TCTI_CONTEXT **context) {

    UNUSED(nameConf);
    printf("fml\n");
    TSS2_RC rc = mock_type(TSS2_RC);
    if (rc == TSS2_RC_SUCCESS) {
        *context = mock_type(TSS2_TCTI_CONTEXT*);
    }

    return rc;
}

static TSS2_TCTI_CONTEXT_COMMON_V2 tcti_instance;

static void common_prelude(void) {
    /*
     * NULL getenv for the tcti config results
     * in a default TCTI based on a probe using dlopen().
     *
     * If we find that tcti, we return the tcti conf, which
     * then results in us following the normal tcti loading logic.
     */
    set_getenv(TPM2TOOLS_ENV_TCTI, NULL);
    /* mock Tss2_TctiLdr_Initialize */
    will_return (__wrap_Tss2_TctiLdr_Initialize, TSS2_RC_SUCCESS);
    will_return (__wrap_Tss2_TctiLdr_Initialize, &tcti_instance);
}

static void test_null_tcti_getenv_no_errata(void **state) {
    UNUSED(state);

    char *argv[] = {
        "program",
        "-Z"      // Disable errata getenv call
    };

    int argc = ARRAY_LEN(argv);

    tpm2_options *tool_opts = NULL;
    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;

    common_prelude();

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
}

static void test_null_tcti_getenv_with_errata(void **state) {
    UNUSED(state);

    char *argv[] = {
        "program",
                    // Enable errata getenv call via no -Z
    };

    int argc = ARRAY_LEN(argv);

    tpm2_options *tool_opts = NULL;
    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;

    common_prelude();

    set_getenv(TPM2TOOLS_ENV_ENABLE_ERRATA, NULL);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
}

static void test_tcti_short_option_no_errata(void **state) {
    UNUSED(state);

    char *argv[] = {
        "program",
        "-T",      // Set TCTI to something specific
        "tctifake",
        "-Z"       // Disable errata getenv call
    };

    int argc = ARRAY_LEN(argv);

    tpm2_options *tool_opts = NULL;
    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;

    /* we never call getenv() because we use -T */
    /* we never probe for a tcti */
    /* we just use what is given, in this case, return a mocked instance */
    will_return(__wrap_Tss2_TctiLdr_Initialize, TSS2_RC_SUCCESS);
    will_return(__wrap_Tss2_TctiLdr_Initialize, &tcti_instance);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
}

static void test_tcti_long_option_with_equals_no_errata(void **state) {
    UNUSED(state);

    char *argv[] = {
        "program",
        "--tcti=tctifake",    // Set TCTI to something specific
        "-Z"                  // Disable errata getenv call
    };

    int argc = ARRAY_LEN(argv);

    tpm2_options *tool_opts = NULL;
    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;

    /* we never call getenv() because we use -T */
    /* we never probe for a tcti */
    /* we just use what is given, in this case, return a mocked instance */
    will_return(__wrap_Tss2_TctiLdr_Initialize, TSS2_RC_SUCCESS);
    will_return(__wrap_Tss2_TctiLdr_Initialize, &tcti_instance);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
}

static void test_tcti_long_option_no_equals_no_errata(void **state) {
    UNUSED(state);

    char *argv[] = {
        "program",
        "--tcti",             // Set TCTI to something specific
        "tctifake",
        "-Z"                  // Disable errata getenv call
    };

    int argc = ARRAY_LEN(argv);

    tpm2_options *tool_opts = NULL;
    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;

    /* we never call getenv() because we use -T */
    /* we never probe for a tcti */
    /* we just use what is given, in this case, return a mocked instance */
    will_return(__wrap_Tss2_TctiLdr_Initialize, TSS2_RC_SUCCESS);
    will_return(__wrap_Tss2_TctiLdr_Initialize, &tcti_instance);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
}

static void test_invalid_tcti_no_errata(void **state) {
    UNUSED(state);

    char *argv[] = {
        "program",
        "-T",      // Set TCTI to something specific
        "tctiinvalid",
        "-Z"       // Disable errata getenv call
    };

    int argc = ARRAY_LEN(argv);

    tpm2_options *tool_opts = NULL;
    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;

    will_return(__wrap_Tss2_TctiLdr_Initialize, TSS2_TCTI_RC_NOT_SUPPORTED);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_int_equal(oc, tpm2_option_code_err);
}

/*
 * link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_null_tcti_getenv_no_errata),
            cmocka_unit_test(test_null_tcti_getenv_with_errata),
            cmocka_unit_test(test_tcti_short_option_no_errata),
            cmocka_unit_test(test_tcti_long_option_no_equals_no_errata),
            cmocka_unit_test(test_tcti_long_option_with_equals_no_errata),
            cmocka_unit_test(test_invalid_tcti_no_errata),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
