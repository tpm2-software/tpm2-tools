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

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "tpm2_alg_util.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct expected_data expected_data;
struct expected_data {
    struct {
        ESYS_TR key;
        ESYS_TR bind;
        TPM2_SE session_type;
        TPMT_SYM_DEF symmetric;
        TPMI_ALG_HASH auth_hash;
        TPM2B_NONCE nonce_caller;
    } input;

    struct output {
        ESYS_TR handle;
        TPM2_RC rc;
    } output;
};

static inline void set_expected(ESYS_TR key, ESYS_TR bind,
        TPM2_SE session_type,
        TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH auth_hash,
        TPM2B_NONCE *nonce_caller, ESYS_TR handle, TPM2_RC rc) {

    expected_data *e = calloc(1, sizeof(*e));
    assert_non_null(e);

    e->input.key = key;
    e->input.bind = bind;
    e->input.session_type = session_type;
    e->input.symmetric = *symmetric;
    e->input.auth_hash = auth_hash;
    e->input.nonce_caller = *nonce_caller;

    e->output.handle = handle;
    e->output.rc = rc;

    will_return(__wrap_Esys_StartAuthSession, e);
}

static inline void set_expected_defaults(TPM2_SE session_type,
        ESYS_TR handle, TPM2_RC rc) {

    TPMT_SYM_DEF symmetric;
    memset(&symmetric, 0, sizeof(symmetric));
    symmetric.algorithm = TPM2_ALG_NULL;

    TPM2B_NONCE nonce_caller;
    memset(&nonce_caller, 0, sizeof(nonce_caller));
    nonce_caller.size = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA1);

    set_expected(
    ESYS_TR_NONE,
    ESYS_TR_NONE, session_type, &symmetric,
    TPM2_ALG_SHA256, &nonce_caller, handle, rc);
}

TSS2_RC __wrap_Esys_StartAuthSession(ESYS_CONTEXT *esysContext,
            ESYS_TR tpmKey, ESYS_TR bind,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
            const TPM2B_NONCE *nonceCaller, TPM2_SE sessionType,
            const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
            ESYS_TR *sessionHandle) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(sessionHandle);

    expected_data *e = mock_ptr_type(expected_data *);

    assert_int_equal(tpmKey, e->input.key);

    assert_int_equal(bind, e->input.bind);

    assert_memory_equal(nonceCaller, &e->input.nonce_caller,
            sizeof(*nonceCaller));

    assert_int_equal(sessionType, e->input.session_type);

    assert_memory_equal(symmetric, &e->input.symmetric,
            sizeof(*symmetric));

    assert_int_equal(authHash, e->input.auth_hash);

    *sessionHandle = e->output.handle;

    TSS2_RC rc = e->output.rc;
    free(e);
    return rc;
}

ESYS_TR _save_handle;

static void test_tpm2_create_dummy_context(TPMS_CONTEXT *context) {
    context->hierarchy = TPM2_RH_ENDORSEMENT;
    context->savedHandle = 2147483648;
    context->sequence = 10;
    context->contextBlob.size = 200;
    memset(context->contextBlob.buffer, '\0', context->contextBlob.size);
}

TSS2_RC __wrap_Esys_ContextSave(ESYS_CONTEXT *esysContext,
            ESYS_TR saveHandle, TPMS_CONTEXT **context) {

    UNUSED(esysContext);

    // context should be non-null or bool files_save_tpm_context_to_file()
    // segfaults
    TPMS_CONTEXT *dummy_context = calloc(1, sizeof(TPMS_CONTEXT));
    test_tpm2_create_dummy_context(dummy_context);
    *context = dummy_context;
    _save_handle = saveHandle;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_ContextLoad(ESYS_CONTEXT *esysContext,
            const TPMS_CONTEXT *context, ESYS_TR *loadedHandle) {

    UNUSED(esysContext);
    UNUSED(context);

    *loadedHandle = _save_handle;

    return TPM2_RC_SUCCESS;
}

static TSS2_RC policy_restart_return() {
    return (TSS2_RC)mock();
}

TSS2_RC __wrap_Esys_PolicyRestart(ESYS_CONTEXT *esysContext,
            ESYS_TR sessionHandle,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3) {

    UNUSED(esysContext);
    UNUSED(sessionHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    return policy_restart_return();
}

#define CONTEXT   ((ESYS_CONTEXT *)0xDEADBEEF)
#define SESSION_HANDLE 0xBADC0DE

TSS2_RC __wrap_Esys_TR_GetName(ESYS_CONTEXT *esysContext, ESYS_TR handle,
            TPM2B_NAME **name) {

    UNUSED(esysContext);
    UNUSED(handle);

    *name = malloc(sizeof(TPM2B_NAME));
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2_HANDLE_Marshal(SESSION_HANDLE,
                    &(*name)->name[0], sizeof(TPM2_HANDLE), &offset);
    (*name)->size = offset;

    return rc;
}


static void test_tpm2_session_defaults_good(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(CONTEXT, d);
    assert_non_null(s);

    ESYS_TR handle = tpm2_session_get_handle(s);
    assert_int_equal(handle, SESSION_HANDLE);

    TPMI_ALG_HASH auth_hash = tpm2_session_get_authhash(s);
    assert_int_equal(auth_hash, TPM2_ALG_SHA256);

    tpm2_session_free(&s);
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

    set_expected(0x1234, 42,
    TPM2_SE_TRIAL, &symmetric,
    TPM2_ALG_SHA512, &nonce,
    SESSION_HANDLE,
    TPM2_RC_SUCCESS);

    tpm2_session *s = tpm2_session_new(CONTEXT, d);
    assert_non_null(s);

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(s);
    assert_int_equal(handle, SESSION_HANDLE);

    TPMI_ALG_HASH auth_hash = tpm2_session_get_authhash(s);
    assert_int_equal(auth_hash, TPM2_ALG_SHA512);

    tpm2_session_free(&s);
    assert_null(s);
}

static void test_tpm2_session_defaults_bad(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_FAILURE);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(CONTEXT, d);
    assert_null(s);
}

static int test_session_setup(void **state) {

    int rc = (*state = tmpnam(NULL)) == NULL;
    return rc;
}

static int test_session_teardown(void **state) {

    int rc = unlink((char *)*state);
    return rc;
}

static void test_tpm2_session_save(void **state) {

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(CONTEXT, d);
    assert_non_null(s);

    ESYS_TR handle1 = tpm2_session_get_handle(s);
    TPMI_SH_AUTH_SESSION tpm_handle1;
    bool result = tpm2_util_esys_handle_to_sys_handle(CONTEXT, handle1,
                    &tpm_handle1);
    assert_true(result);

    result = tpm2_session_save(CONTEXT, s, (char *)*state);
    assert_true(result);

    tpm2_session_free(&s);
    assert_null(s);

    s = tpm2_session_restore(NULL, (char *)*state);
    assert_non_null(s);

    ESYS_TR handle2 = tpm2_session_get_handle(s);
    TPMI_SH_AUTH_SESSION tpm_handle2;
    result = tpm2_util_esys_handle_to_sys_handle(CONTEXT, handle2,
                &tpm_handle2);
    assert_true(result);

    assert_int_equal(tpm_handle1, tpm_handle2);

    tpm2_session_free(&s);
    assert_null(s);
}

static void test_tpm2_session_restart(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(CONTEXT, d);
    assert_non_null(s);

    will_return(policy_restart_return, TPM2_RC_SUCCESS);
    bool result = tpm2_session_restart(CONTEXT, s);
    assert_true(result);

    will_return(policy_restart_return, TPM2_RC_HANDLE);
    result = tpm2_session_restart(CONTEXT, s);
    assert_false(result);

    tpm2_session_free(&s);
    assert_null(s);
}

static void test_tpm2_session_is_trial_test(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_TRIAL, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_TRIAL);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(CONTEXT, d);
    assert_non_null(s);

    TPM2_SE type = tpm2_session_get_type(s);
    assert_int_equal(type, TPM2_SE_TRIAL);

    bool is_trial = tpm2_session_is_trial(s);
    assert_true(is_trial);

    tpm2_session_free(&s);
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
