/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_auth_util.h"
#include "tpm2_auth_util.c" /* we want to test the static function parse_pcr */

#include "esys_stubs.h"
#include "test_session_common.h"

TSS2_RC __wrap_Esys_TR_SetAuth(ESYS_CONTEXT *esysContext, ESYS_TR handle,
        TPM2B_AUTH const *authValue) {
    UNUSED(esysContext);
    UNUSED(handle);
    UNUSED(authValue);

    return TPM2_RC_SUCCESS;
}

static ESYS_CONTEXT *expected_name_alg_context;
static ESYS_TR expected_name_alg_handle;
static TPM2_ALG_ID mocked_name_alg;
static bool name_alg_expected;
static bool capability_get_expected;

TPM2_ALG_ID __wrap_tpm2_alg_util_get_name_alg(ESYS_CONTEXT *ectx,
        ESYS_TR handle) {

    assert_true(name_alg_expected);
    name_alg_expected = false;
    assert_ptr_equal(ectx, expected_name_alg_context);
    assert_int_equal(handle, expected_name_alg_handle);
    return mocked_name_alg;
}

tool_rc __wrap_tpm2_capability_get(ESYS_CONTEXT *context,
        TPM2_CAP capability, UINT32 property, UINT32 count,
        TPMS_CAPABILITY_DATA **capability_data) {

    assert_true(capability_get_expected);
    capability_get_expected = false;
    assert_ptr_equal(context, expected_name_alg_context);
    assert_int_equal(capability, TPM2_CAP_ALGS);
    assert_int_equal(property, 0);
    assert_int_equal(count, TPM2_MAX_CAP_ALGS);
    assert_non_null(capability_data);
    *capability_data = NULL;

    return tool_rc_general_error;
}

tool_rc __wrap_tpm2_policy_build_pcr(ESYS_CONTEXT *context,
        tpm2_session *policy_session, const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections, TPM2B_DIGEST *raw_pcr_digest,
        tpm2_forwards *forwards) {

    assert_ptr_equal(context, expected_name_alg_context);
    assert_non_null(policy_session);
    assert_null(raw_pcrs_file);
    assert_null(raw_pcr_digest);
    assert_null(forwards);
    assert_int_equal(pcr_selections->count, 1);
    assert_int_equal(pcr_selections->pcrSelections[0].hash, TPM2_ALG_SHA256);
    assert_int_equal(pcr_selections->pcrSelections[0].sizeofSelect, 3);
    assert_true(pcr_selections->pcrSelections[0].pcrSelect[0] & 1);

    return tool_rc_success;
}

static void test_tpm2_auth_util_from_optarg_raw_noprefix(void **state) {
    (void) state;

    tpm2_session *session;
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "abcd", &session, true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 4);
    assert_memory_equal(auth->buffer, "abcd", 4);

    tpm2_session_close(&session);
}

static void test_tpm2_auth_util_from_optarg_str_prefix(void **state) {
    (void) state;

    tpm2_session *session;
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "str:abcd", &session, true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 4);
    assert_memory_equal(auth->buffer, "abcd", 4);

    tpm2_session_close(&session);
}

static void test_tpm2_auth_util_from_optarg_hex_prefix(void **state) {
    (void) state;

    tpm2_session *session;
    BYTE expected[] = { 0x12, 0x34, 0xab, 0xcd };

    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "hex:1234abcd", &session,
            true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, sizeof(expected));
    assert_memory_equal(auth->buffer, expected, sizeof(expected));

    tpm2_session_close(&session);
}

static void test_tpm2_auth_util_from_optarg_str_escaped_hex_prefix(
        void **state) {
    (void) state;

    tpm2_session *session;

    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "str:hex:1234abcd", &session,
            true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 12);
    assert_memory_equal(auth->buffer, "hex:1234abcd", 12);

    tpm2_session_close(&session);
}

FILE * __real_fopen(const char *path, const char *mode);
FILE * __wrap_fopen(const char *path, const char *mode) {
    return __real_fopen(path, mode);
}

size_t __real_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return __real_fread(ptr, size, nmemb, stream);
}

long __real_ftell(FILE *stream);
long __wrap_ftell(FILE *stream) {
    return __real_ftell(stream);
}

int __real_fseek(FILE *stream, long offset, int whence);
int __wrap_fseek(FILE *stream, long offset, int whence) {
    return __real_fseek(stream, offset, whence);
}

int __real_feof(FILE *stream);
int __wrap_feof(FILE *stream) {
    return __real_feof(stream);
}

int __real_fclose(FILE *stream);
int __wrap_fclose(FILE *stream) {
    return __real_fclose(stream);
}

static void test_tpm2_auth_util_from_optarg_file(void **state) {
    UNUSED(state);

    tpm2_session *session;
    ssize_t n;
    int fd;
    const char *password = "sekretpasswrd";
    char file_path[] = "file:/tmp/test_tpm2_auth_util_foobar-XXXXXXXXXX";
    char *path = &file_path[strlen("file:")];

    fd = mkstemp(path);
    assert_true(fd >= 0);
    n = write(fd, password, strlen(password));
    assert_int_equal(n, strlen(password));
    close(fd);

    tool_rc rc = tpm2_auth_util_from_optarg(NULL, file_path, &session, true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, strlen(password));
    assert_memory_equal(auth->buffer, password, strlen(password));

    tpm2_session_close(&session);
    unlink(path);
}

static void test_pcr_auth_with_name_alg(void **state, TPM2_ALG_ID name_alg,
        TPMI_ALG_HASH expected_session_hash, bool expect_capability_get) {

    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *)*state;
    ESYS_TR auth_handle = 0x81000000;
    tpm2_session *session = NULL;

    expected_name_alg_context = ectx;
    expected_name_alg_handle = auth_handle;
    mocked_name_alg = name_alg;
    name_alg_expected = true;
    capability_get_expected = expect_capability_get;

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };
    TPM2B_NONCE nonce_caller = {
        .size = tpm2_alg_util_get_hash_size(expected_session_hash),
    };
    set_expected(ESYS_TR_NONE, ESYS_TR_NONE, TPM2_SE_POLICY, &symmetric,
            expected_session_hash, &nonce_caller, SESSION_HANDLE,
            TPM2_RC_SUCCESS);

    tool_rc rc = tpm2_auth_util_from_optarg_with_auth_handle(ectx,
            "pcr:sha256:0", &session, false, auth_handle);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(session);
    assert_false(name_alg_expected);
    assert_false(capability_get_expected);

    tpm2_session_close(&session);
}

static void test_tpm2_auth_util_from_optarg_with_auth_handle_pcr(void **state) {

    test_pcr_auth_with_name_alg(state, TPM2_ALG_SM3_256,
            TPM2_ALG_SM3_256, false);
}

static void test_pcr_auth_name_alg_error_uses_fallback(void **state) {

    test_pcr_auth_with_name_alg(state, TPM2_ALG_ERROR, TPM2_ALG_SHA256, true);
}

static void test_pcr_auth_non_hash_name_alg_uses_fallback(void **state) {

    test_pcr_auth_with_name_alg(state, TPM2_ALG_RSA, TPM2_ALG_SHA256, true);
}

static void test_auth_handle_entry_delegates_non_pcr(void **state) {

    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *)*state;
    expected_name_alg_context = ectx;
    name_alg_expected = false;
    capability_get_expected = true;
    set_expected_defaults(TPM2_SE_HMAC, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session *session = NULL;
    tool_rc rc = tpm2_auth_util_from_optarg_with_auth_handle(ectx, "secret",
            &session, false, 0x81000000);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(session);
    assert_false(name_alg_expected);
    assert_false(capability_get_expected);

    tpm2_session_close(&session);
}

#define PCR_SPECIFICATION "sha256:0,1,2,3+sha1:0,1,2,3"
#define PCR_FILE "raw-pcr-file"

static void test_parse_pcr_no_raw_file(void **state) {
    UNUSED(state);

    const char *policy = "pcr:" PCR_SPECIFICATION;

    char *pcr_str, *raw_file;

    bool ret = parse_pcr(policy, &pcr_str, &raw_file);
    assert_true(ret);
    assert_string_equal(pcr_str, PCR_SPECIFICATION);
    assert_null(raw_file);

    free(pcr_str);
}

static void test_parse_pcr_with_raw_file(void **state) {
    UNUSED(state);

    const char *policy = "pcr:" PCR_SPECIFICATION "=" PCR_FILE;

    char *pcr_str, *raw_file;

    bool ret = parse_pcr(policy, &pcr_str, &raw_file);
    assert_true(ret);
    assert_string_equal(pcr_str, PCR_SPECIFICATION);
    assert_string_equal(raw_file, PCR_FILE);

    free(pcr_str);
}

static void test_tpm2_auth_util_from_optarg_raw_overlength(void **state) {
    (void) state;

    tpm2_session *session = NULL;
    char *overlength =
        "this_password_is_over_64_characters_in_length_and_should_fail_XXX";
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, overlength, &session, true);
    assert_int_equal(rc, tool_rc_general_error);
    assert_null(session);
}

static void test_tpm2_auth_util_from_optarg_hex_overlength(void **state) {
    (void) state;

    tpm2_session *session = NULL;
    /* 65 hex chars generated via: echo \"`xxd -p -c256 -l65 /dev/urandom`\"\; */
    char *overlength =
        "hex:ae6f6fa01589aa7b227bb6a34c7a8e0c273adbcf14195ce12391a5cc12a5c271f62088"
        "dbfcf1914fdf120da183ec3ad6cc78a2ffd91db40a560169961e3a6d26bf";
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, overlength, &session, false);
    assert_int_equal(rc, tool_rc_general_error);
    assert_null(session);
}

static void test_tpm2_auth_util_from_optarg_empty_str(void **state) {
    (void) state;

    tpm2_session *session;

    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "", &session, true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 0);

    tpm2_session_close(&session);
}

static void test_tpm2_auth_util_from_optarg_empty_str_str_prefix(
    void **state) {
    (void) state;

    tpm2_session *session;

    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "str:", &session, true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 0);

    tpm2_session_close(&session);
}

static void test_tpm2_auth_util_from_optarg_empty_str_hex_prefix(
    void **state) {
    (void) state;

    tpm2_session *session;

    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "hex:", &session, true);
    assert_int_equal(rc, tool_rc_success);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    assert_int_equal(auth->size, 0);

    tpm2_session_close(&session);
}

static void test_parse_pcr_empty(void **state) {
    UNUSED(state);

    const char *policy = "pcr:";

    char *pcr_str, *raw_file;

    bool ret = parse_pcr(policy, &pcr_str, &raw_file);
    assert_false(ret);
}

static void test_parse_pcr_empty_pcr_specification(void **state) {
    UNUSED(state);

    const char *policy = "pcr:=" PCR_FILE;

    char *pcr_str, *raw_file;

    bool ret = parse_pcr(policy, &pcr_str, &raw_file);
    assert_false(ret);
}

static void test_parse_pcr_empty_pcr_file(void **state) {
    UNUSED(state);

    const char *policy = "pcr:" PCR_SPECIFICATION "=";

    char *pcr_str, *raw_file;

    bool ret = parse_pcr(policy, &pcr_str, &raw_file);
    assert_false(ret);

    free(pcr_str);
}

static int setup(void **state) {
    TSS2_RC rc;
    ESYS_CONTEXT *ectx;
    size_t size = sizeof(TSS2_TCTI_CONTEXT_FAKE);
    TSS2_TCTI_CONTEXT *tcti = malloc(size);
    assert_non_null(tcti);

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
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, "fakepass",
            &s, true);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    rc = tpm2_auth_util_get_shandle(ectx, auth_handle, s, &shandle);
    assert_int_equal(rc, tool_rc_success);
    assert_true(shandle == ESYS_TR_PASSWORD);
    tpm2_session_close(&s);
    assert_null(s);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    rc = tpm2_session_open(ectx, d, &s);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    rc = tpm2_auth_util_get_shandle(ectx, auth_handle, s, &shandle);
    assert_int_equal(rc, tool_rc_success);
    assert_int_equal(SESSION_HANDLE, shandle);

    tpm2_session_close(&s);
    assert_null(s);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_raw_noprefix),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_str_prefix),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_hex_prefix),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_str_escaped_hex_prefix),

            cmocka_unit_test_setup_teardown(test_tpm2_auth_util_get_pw_shandle,
                                            setup, teardown),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_file),
            cmocka_unit_test_setup_teardown(
                    test_tpm2_auth_util_from_optarg_with_auth_handle_pcr,
                    setup, teardown),
            cmocka_unit_test_setup_teardown(
                    test_pcr_auth_name_alg_error_uses_fallback,
                    setup, teardown),
            cmocka_unit_test_setup_teardown(
                    test_pcr_auth_non_hash_name_alg_uses_fallback,
                    setup, teardown),
            cmocka_unit_test_setup_teardown(
                    test_auth_handle_entry_delegates_non_pcr,
                    setup, teardown),

            cmocka_unit_test(test_parse_pcr_no_raw_file),
            cmocka_unit_test(test_parse_pcr_with_raw_file),

            /* negative testing */
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_raw_overlength),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_hex_overlength),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_empty_str),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_empty_str_str_prefix),
            cmocka_unit_test(test_tpm2_auth_util_from_optarg_empty_str_hex_prefix),
            cmocka_unit_test(test_parse_pcr_empty),
            cmocka_unit_test(test_parse_pcr_empty_pcr_specification),
            cmocka_unit_test(test_parse_pcr_empty_pcr_file),
    };

return cmocka_run_group_tests(tests, NULL, NULL);
}
