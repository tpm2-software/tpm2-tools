/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "tpm2_util.h"
#include "tpm2_auth_util.h"

#include "esys_stubs.h"
#include "test_session_common.h"

TSS2_RC __wrap_Esys_TR_SetAuth(ESYS_CONTEXT *esysContext, ESYS_TR handle,
			TPM2B_AUTH const *authValue) {
	UNUSED(esysContext);
	UNUSED(handle);
	UNUSED(authValue);

	return TPM2_RC_SUCCESS;
}

static void test_tpm2_password_util_from_optarg_raw_noprefix(void **state) {
    (void)state;

    tpm2_session *session;
    bool res = tpm2_auth_util_from_optarg(NULL, "abcd", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 4);
    assert_memory_equal(auth->buffer, "abcd", 4);

    tpm2_session_close(&session);
}

static void test_tpm2_password_util_from_optarg_str_prefix(void **state) {
    (void)state;

    tpm2_session *session;
    bool res = tpm2_auth_util_from_optarg(NULL, "str:abcd", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 4);
    assert_memory_equal(auth->buffer, "abcd", 4);

    tpm2_session_close(&session);
}

static void test_tpm2_password_util_from_optarg_hex_prefix(void **state) {
    (void)state;

    tpm2_session *session;
    BYTE expected[] = {
            0x12, 0x34, 0xab, 0xcd
    };

    bool res = tpm2_auth_util_from_optarg(NULL, "hex:1234abcd", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, sizeof(expected));
    assert_memory_equal(auth->buffer, expected, sizeof(expected));

    tpm2_session_close(&session);
}

static void test_tpm2_password_util_from_optarg_str_escaped_hex_prefix(void **state) {
    (void)state;

    tpm2_session *session;

    bool res = tpm2_auth_util_from_optarg(NULL, "str:hex:1234abcd", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 12);
    assert_memory_equal(auth->buffer, "hex:1234abcd", 12);

    tpm2_session_close(&session);
}

FILE mocked_file_stream;
const char *mocked_file_data = "sekretpasswrd";

FILE * __real_fopen(const char *path, const char *mode);
FILE * __wrap_fopen(const char *path, const char *mode) {
    if (strcmp (path, "test_tpm2_auth_util_foobar")) {
        printf("REAL CALLED\n");
        return __real_fopen(path, mode);
    }
    return mock_ptr_type(FILE*);
}

size_t __real_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (stream != &mocked_file_stream) {
        return __real_fread(ptr,size,nmemb,stream);
    }
    UNUSED(stream);
    memcpy(ptr, mocked_file_data, size * nmemb);
    return mock_type (size_t);
}

long __real_ftell(FILE *stream);
long __wrap_ftell(FILE *stream) {
    if (stream != &mocked_file_stream) {
        return __real_ftell(stream);
    }
    UNUSED(stream);
    return mock_type (long);
}

int __real_fseek(FILE *stream, long offset, int whence);
int __wrap_fseek(FILE *stream, long offset, int whence) {
    if (stream != &mocked_file_stream) {
        return __real_fseek(stream, offset, whence);
    }
    UNUSED(stream);
    UNUSED(offset);
    UNUSED(whence);
    return 0;
}

int __real_fclose(FILE *stream);
int __wrap_fclose(FILE *stream) {
    if (stream != &mocked_file_stream) {
        return __real_fclose(stream);
    }
    UNUSED(stream);
    return 0;
}

static void test_tpm2_password_util_from_optarg_file(void **state) {
    UNUSED(state);

    tpm2_session *session;

    will_return(__wrap_fopen, &mocked_file_stream);

    will_return(__wrap_fread, (size_t)strlen(mocked_file_data));

    will_return(__wrap_ftell, (long)strlen(mocked_file_data));
    will_return(__wrap_ftell, (long)strlen(mocked_file_data));

    bool res = tpm2_auth_util_from_optarg(NULL,
        "file:test_tpm2_auth_util_foobar", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, strlen(mocked_file_data));
    assert_memory_equal(auth->buffer, mocked_file_data, strlen(mocked_file_data));

    tpm2_session_close(&session);
}

static void test_tpm2_password_util_from_optarg_raw_overlength(void **state) {
    (void)state;

    tpm2_session *session = NULL;
    char *overlength = "this_password_is_over_64_characters_in_length_and_should_fail_XXX";
    bool res = tpm2_auth_util_from_optarg(NULL, overlength, &session, true);
    assert_false(res);
    assert_null(session);
}

static void test_tpm2_password_util_from_optarg_hex_overlength(void **state) {
    (void)state;

    tpm2_session *session = NULL;
    /* 65 hex chars generated via: echo \"`xxd -p -c256 -l65 /dev/urandom`\"\; */
    char *overlength =
        "hex:ae6f6fa01589aa7b227bb6a34c7a8e0c273adbcf14195ce12391a5cc12a5c271f62088"
        "dbfcf1914fdf120da183ec3ad6cc78a2ffd91db40a560169961e3a6d26bf";
    bool res = tpm2_auth_util_from_optarg(NULL, overlength, &session, false);
    assert_false(res);
    assert_null(session);
}

static void test_tpm2_password_util_from_optarg_empty_str(void **state) {
    (void)state;

    tpm2_session *session;

    bool res = tpm2_auth_util_from_optarg(NULL, "", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 0);

    tpm2_session_close(&session);
}

static void test_tpm2_password_util_from_optarg_empty_str_str_prefix(void **state) {
    (void)state;

    tpm2_session *session;

    bool res = tpm2_auth_util_from_optarg(NULL, "str:", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 0);

    tpm2_session_close(&session);
}


static void test_tpm2_password_util_from_optarg_empty_str_hex_prefix(void **state) {
    (void)state;

    tpm2_session *session;

    bool res = tpm2_auth_util_from_optarg(NULL, "hex:", &session, true);
    assert_true(res);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 0);

    tpm2_session_close(&session);
}

static int setup(void **state) {
    TSS2_RC rc;
    ESYS_CONTEXT *ectx;
    size_t size = sizeof(TSS2_TCTI_CONTEXT_FAKE);
    TSS2_TCTI_CONTEXT *tcti = malloc(size);

    rc = tcti_fake_initialize(tcti, &size);
    if (rc) {
      return (int)rc;
    }
    rc = Esys_Initialize(&ectx, tcti, NULL);
    *state = (void *)ectx;
    return (int)rc;
}

static int teardown(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *)*state;
    Esys_GetTcti(ectx, &tcti);
    Esys_Finalize(&ectx);
    free(tcti);
    return 0;
}

static void test_tpm2_auth_util_get_pw_shandle(void **state) {

    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *)*state;
    ESYS_TR auth_handle = ESYS_TR_NONE;
    ESYS_TR shandle;

    tpm2_session *s;
    bool result = tpm2_auth_util_from_optarg(NULL, "fakepass",
            &s, true);
    assert_true(result);
    assert_non_null(s);

    shandle = tpm2_auth_util_get_shandle(ectx, auth_handle, s);
    assert_true(shandle == ESYS_TR_PASSWORD);
    tpm2_session_close(&s);
    assert_null(s);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    s = tpm2_session_open(ectx, d);
    assert_non_null(s);

    shandle = tpm2_auth_util_get_shandle(ectx, auth_handle, s);
    assert_int_equal(SESSION_HANDLE, shandle);

    tpm2_session_close(&s);
    assert_null(s);
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

            cmocka_unit_test_setup_teardown(test_tpm2_auth_util_get_pw_shandle,
                                            setup, teardown),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_file),

            /* negative testing */
            cmocka_unit_test(test_tpm2_password_util_from_optarg_raw_overlength),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_hex_overlength),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str_str_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str_hex_prefix)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
