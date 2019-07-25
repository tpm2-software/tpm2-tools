/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_options.h"
#include "tpm2_tcti_ldr.h"
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

static void set_dlsym(void *handle, const char *symbol, void *ret) {

    test_pair *e = calloc(1, sizeof(test_pair));
    assert_non_null(e);

    e->input[0].v = handle;
    e->input[1].cn = symbol;
    e->output.v = ret;

    will_return(__wrap_tpm2_util_dlsym, e);
}

static void set_dlopen(const char *name, void *ret) {

    test_pair *e = calloc(1, sizeof(test_pair));
    assert_non_null(e);

    e->input[0].cn = name;
    e->output.v = ret;

    will_return(__wrap_tpm2_util_dlopen, e);
}

static void set_dlclose(void *expected, int ret) {

    test_pair *e = calloc(1, sizeof(test_pair));
    assert_non_null(e);

    e->input[0].v = expected;
    e->output.i = ret;

    will_return(__wrap_tpm2_util_dlclose, e);
}

static void set_getenv(const char *name, char *ret) {

    test_pair *e = calloc(1, sizeof(test_pair));
    assert_non_null(e);

    e->input[0].cn = name;
    e->output.s = ret;

    will_return(__wrap_tpm2_util_getenv, e);
}

void *__wrap_tpm2_util_dlopen(const char *filename, int flags) {
    UNUSED(flags);

    test_pair *x = mock_ptr_type(test_pair *);

    const char *expected_filename = x->input[0].cn;
    void *ret = x->output.v;
    free(x);

    assert_string_equal(filename, expected_filename);

    return ret;
}

#define HANDLE_SKIP_CHECK ((void *) -1)

int __wrap_tpm2_util_dlclose(void *handle) {

    test_pair *x = mock_ptr_type(test_pair *);

    void *expected_handle = x->input[0].v;
    int ret = x->output.i;
    free(x);
    if (expected_handle != HANDLE_SKIP_CHECK) {
        assert_ptr_equal(expected_handle, handle);
    }

    return ret;
}

char *__wrap_tpm2_util_getenv(const char *name) {

    test_pair *x = mock_ptr_type(test_pair *);

    const char *expected_name = x->input[0].cn;
    char *ret = x->output.s;
    free(x);

    assert_string_equal(name, expected_name);

    return ret;
}

void *__wrap_tpm2_util_dlsym(void *handle, const char *symbol) {

    test_pair *x = mock_ptr_type(test_pair *);

    void *expected_handle = x->input[0].v;
    const char *expected_symbol = x->input[1].cn;
    void *ret = x->output.v;
    free(x);

    assert_ptr_equal(handle, expected_handle);
    assert_string_equal(symbol, expected_symbol);

    return ret;
}
/*
 * implement a dummy TCTI
 */
static TSS2_RC tcti_receive (TSS2_TCTI_CONTEXT *context,
                   size_t *size,
                   uint8_t *response,
                   int32_t timeout) {
    UNUSED(context);
    UNUSED(size);
    UNUSED(response);
    UNUSED(timeout);

    return TSS2_RC_SUCCESS;
}

TSS2_RC tcti_transmit (TSS2_TCTI_CONTEXT *context,
                    size_t size,
                    const uint8_t *command) {
    UNUSED(context);
    UNUSED(size);
    UNUSED(command);

    return TSS2_RC_SUCCESS;
}

void tcti_finalize (TSS2_TCTI_CONTEXT *context) {
    UNUSED(context);
}

static TSS2_RC tcti_init(
    TSS2_TCTI_CONTEXT *context,
    size_t *size,
    const char *config) {

    UNUSED(config);

    if (size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    if (context == NULL) {
        *size = sizeof(TSS2_TCTI_CONTEXT_COMMON_V2);
        return TSS2_RC_SUCCESS;
    }

    TSS2_TCTI_MAGIC (context) = 0x9886dc39e78df261;
    TSS2_TCTI_VERSION (context) = 1;

    TSS2_TCTI_TRANSMIT (context) = tcti_transmit;
    TSS2_TCTI_RECEIVE (context) = tcti_receive;
    TSS2_TCTI_FINALIZE (context) = tcti_finalize;
    TSS2_TCTI_CANCEL (context) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (context) = NULL;
    TSS2_TCTI_SET_LOCALITY (context) = NULL;
    TSS2_TCTI_MAKE_STICKY (context) = NULL;

    return TSS2_RC_SUCCESS;
}

static const TSS2_TCTI_INFO *tcti_info_func(void) {
    static const TSS2_TCTI_INFO info = {
       .config_help = "dummy config help",
       .description = "dummy description",
       .init = tcti_init,
       .name = "dummy tcti",
       .version = 0x42
    };

    return &info;
}

#define DLOPEN_HANDLE ((void *)0xDEADBEEF)
#define DLSYM_HANDLE  ((void *)0xBADCC0DE)
#define EXPECTED_DEFAULT_TCTI_SONAME "libtss2-tcti-tabrmd.so.0"
#define EXPECTED_DEFAULT_TCTI_NAME "tabrmd"

static void common_prelude(void) {
    /*
     * NULL getenv for the tcti config results
     * in a default TCTI based on a probe using dlopen().
     *
     * If we find that tcti, we return the tcti conf, which
     * then results in us following the normal tcti loading logic.
     */
    set_getenv(TPM2TOOLS_ENV_TCTI, NULL);
    set_dlopen(EXPECTED_DEFAULT_TCTI_SONAME, DLOPEN_HANDLE);
    set_dlclose(DLOPEN_HANDLE, 0);

    /*
     * After this we try the raw string of tabrmd, which should fail
     */
    set_dlopen(EXPECTED_DEFAULT_TCTI_NAME, NULL);

    /*
     * After this we try the full name, which should work
     */
    set_dlopen(EXPECTED_DEFAULT_TCTI_SONAME, DLOPEN_HANDLE);

    /*
     * Now that we have an open library, we call dlsym to get the tcti info func
     * which will return the dummy tcti
     */
    set_dlsym(DLOPEN_HANDLE, TSS2_TCTI_INFO_SYMBOL, tcti_info_func);
}

static int test_teardown(void **state) {
    UNUSED(state);
#ifndef DISABLE_DLCLOSE
    set_dlclose(HANDLE_SKIP_CHECK, 0);
#endif
    tpm2_tcti_ldr_unload();
    return 0;
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
    free(tcti);
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
    free(tcti);
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
    /* we just use what is given, in this case, we allow it to dlopen */
    set_dlopen("tctifake", DLOPEN_HANDLE);

    /*
     * Now that we have an open library, we call dlsym to get the tcti info func
     * which will return the dummy tcti
     */
    set_dlsym(DLOPEN_HANDLE, TSS2_TCTI_INFO_SYMBOL, tcti_info_func);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
    free(tcti);
}

static void test_tcti_long_option_no_errata(void **state) {
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
    /* we just use what is given, in this case, we allow it to dlopen */
    set_dlopen("tctifake", DLOPEN_HANDLE);

    /*
     * Now that we have an open library, we call dlsym to get the tcti info func
     * which will return the dummy tcti
     */
    set_dlsym(DLOPEN_HANDLE, TSS2_TCTI_INFO_SYMBOL, tcti_info_func);

    tpm2_option_code oc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    assert_non_null(tcti);
    assert_int_equal(oc, tpm2_option_code_continue);
    free(tcti);
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
            cmocka_unit_test_teardown(test_null_tcti_getenv_no_errata,
                    test_teardown),
            cmocka_unit_test_teardown(test_null_tcti_getenv_with_errata,
                    test_teardown),
            cmocka_unit_test_teardown(test_tcti_short_option_no_errata,
                    test_teardown),
            cmocka_unit_test_teardown(test_tcti_long_option_no_errata,
                    test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
