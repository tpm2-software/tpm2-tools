/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include <tss2/tss2_mu.h>

#include "test_session_common.h"
#include "tpm2_session.h"

ESYS_TR _save_handle;

static void test_tpm2_create_dummy_context(TPMS_CONTEXT *context) {
    context->hierarchy = TPM2_RH_ENDORSEMENT;
    context->savedHandle = 2147483648;
    context->sequence = 10;
    context->contextBlob.size = 200;
    memset(context->contextBlob.buffer, '\0', context->contextBlob.size);
}

tool_rc __wrap_tpm2_context_save(ESYS_CONTEXT *esysContext, ESYS_TR saveHandle, bool autoflush,
        TPMS_CONTEXT **context) {

    UNUSED(esysContext);
    UNUSED(autoflush);

    // context should be non-null or bool files_save_tpm_context_to_file()
    // segfaults
    TPMS_CONTEXT *dummy_context = calloc(1, sizeof(TPMS_CONTEXT));
    test_tpm2_create_dummy_context(dummy_context);
    *context = dummy_context;
    _save_handle = saveHandle;

    return tool_rc_success;
}

TSS2_RC __wrap_Esys_ContextLoad(ESYS_CONTEXT *esysContext,
        const TPMS_CONTEXT *context, ESYS_TR *loadedHandle) {

    UNUSED(esysContext);
    UNUSED(context);

    *loadedHandle = _save_handle;

    return TPM2_RC_SUCCESS;
}

static TSS2_RC policy_restart_return() {
    return (TSS2_RC) mock();
}

TSS2_RC __wrap_Esys_PolicyRestart(ESYS_CONTEXT *esysContext,
        ESYS_TR sessionHandle, ESYS_TR shandle1, ESYS_TR shandle2,
        ESYS_TR shandle3) {

    UNUSED(esysContext);
    UNUSED(sessionHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    return policy_restart_return();
}

static ESYS_CONTEXT *CONTEXT = ((ESYS_CONTEXT *) 0xDEADBEEF);

TSS2_RC __wrap_Esys_TR_GetName(ESYS_CONTEXT *esysContext, ESYS_TR handle,
        TPM2B_NAME **name) {

    UNUSED(esysContext);
    UNUSED(handle);

    *name = malloc(sizeof(TPM2B_NAME));
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2_HANDLE_Marshal(SESSION_HANDLE, &(*name)->name[0],
            sizeof(TPM2_HANDLE), &offset);
    (*name)->size = offset;

    return rc;
}

TSS2_RC __wrap_tpm2_flush_context(ESYS_CONTEXT *esysContext,
        ESYS_TR flushHandle) {
    UNUSED(esysContext);
    UNUSED(flushHandle);

    return TSS2_RC_SUCCESS;
}

static void test_tpm2_session_defaults_good(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(CONTEXT, d, &s);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    ESYS_TR handle = tpm2_session_get_handle(s);
    assert_int_equal(handle, SESSION_HANDLE);

    TPMI_ALG_HASH auth_hash = tpm2_session_get_authhash(s);
    assert_int_equal(auth_hash, TPM2_ALG_SHA256);

    tpm2_session_close(&s);
    assert_null(s);
}

static void test_tpm2_session_setters_good(void **state) {
    UNUSED(state);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_TRIAL);
    assert_non_null(d);

    tpm2_session_set_authhash(d, TPM2_ALG_SHA512);

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {
            .aes = 256
        },
        .mode = {
            .aes = 42
        },
    };

    tpm2_session_set_symmetric(d, &symmetric);

    tpm2_session_set_bind(d, 42);

    TPM2B_NONCE nonce = {
        .size = 5,
        .buffer = {
            'n', 'o', 'n', 'c', 'e'
        }
    };

    tpm2_session_set_nonce_caller(d, &nonce);

    tpm2_session_set_key(d, 0x1234);

    set_expected(0x1234, 42, TPM2_SE_TRIAL, &symmetric, TPM2_ALG_SHA512, &nonce,
    SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(CONTEXT, d, &s);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(s);
    assert_int_equal(handle, SESSION_HANDLE);

    TPMI_ALG_HASH auth_hash = tpm2_session_get_authhash(s);
    assert_int_equal(auth_hash, TPM2_ALG_SHA512);

    tpm2_session_close(&s);
    assert_null(s);
}

static void test_tpm2_session_defaults_bad(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_FAILURE);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(CONTEXT, d, &s);
    assert_int_equal(rc, tool_rc_general_error);
    assert_null(s);
}

static int test_session_setup(void **state) {

    int rc = (*state = tmpnam(NULL)) == NULL;
    return rc;
}

static int test_session_teardown(void **state) {

    int rc = unlink((char *) *state);
    return rc;
}

static void test_tpm2_session_save(void **state) {

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session_set_path(d, (char *) *state);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(CONTEXT, d, &s);                    //OPEN
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    rc = tpm2_session_close(&s);                                       //CLOSE
    assert_int_equal(rc, tool_rc_success);
    assert_null(s);

    rc = tpm2_session_restore(NULL, (char *) *state, false, &s);       //RESTORE
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    tpm2_session_close(&s);                                            //CLOSE
    assert_null(s);
}

static void test_tpm2_session_restart(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(CONTEXT, d, &s);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    will_return(policy_restart_return, TPM2_RC_SUCCESS);
    rc = tpm2_session_restart(CONTEXT, s, NULL, TPM2_ALG_NULL);
    assert_int_equal(rc, tool_rc_success);

    will_return(policy_restart_return, TPM2_RC_HANDLE);
    rc = tpm2_session_restart(CONTEXT, s, NULL, TPM2_ALG_NULL);
    assert_int_equal(rc, tool_rc_general_error);

    tpm2_session_close(&s);
    assert_null(s);
}

static void test_tpm2_session_is_trial_test(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_TRIAL, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_TRIAL);
    assert_non_null(d);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(CONTEXT, d, &s);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    TPM2_SE type = tpm2_session_get_type(s);
    assert_int_equal(type, TPM2_SE_TRIAL);

    bool is_trial = tpm2_session_is_trial(s);
    assert_true(is_trial);

    tpm2_session_close(&s);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    const struct CMUnitTest tests[] = {
    /*
     * no_init/bad_init routines must go first as there is no way to
     * de-initialize. However, re-initialization will query the capabilities
     * and can be changed or cause a no-match situation. This is a bit of
     * whitebox knowledge in the ordering of these tests.
     */
    cmocka_unit_test(test_tpm2_session_defaults_good),
    cmocka_unit_test(test_tpm2_session_setters_good),
    cmocka_unit_test(test_tpm2_session_defaults_bad),
    cmocka_unit_test_setup_teardown(test_tpm2_session_save,
            test_session_setup, test_session_teardown),
    cmocka_unit_test(test_tpm2_session_restart),
    cmocka_unit_test(test_tpm2_session_is_trial_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
