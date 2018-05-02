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

#include <tss2/tss2_sys.h>

#include "tpm2_alg_util.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct expected_data expected_data;
struct expected_data {
    struct {
        TPMI_DH_OBJECT key;
        TPMI_DH_ENTITY bind;
        TPM2B_ENCRYPTED_SECRET encrypted_salt;
        TPM2_SE session_type;
        TPMT_SYM_DEF symmetric;
        TPMI_ALG_HASH auth_hash;
        TPM2B_NONCE nonce_caller;
    } input;

    struct output {
        TPMI_SH_AUTH_SESSION handle;
        TPM2_RC rc;
    } output;
};

static inline void set_expected(TPMI_DH_OBJECT key, TPMI_DH_ENTITY bind,
        TPM2B_ENCRYPTED_SECRET *encrypted_salt, TPM2_SE session_type,
        TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH auth_hash,
        TPM2B_NONCE *nonce_caller, TPMI_SH_AUTH_SESSION handle, TPM2_RC rc) {

    expected_data *e = calloc(1, sizeof(*e));
    assert_non_null(e);

    e->input.key = key;
    e->input.bind = bind;
    e->input.encrypted_salt = *encrypted_salt;
    e->input.session_type = session_type;
    e->input.symmetric = *symmetric;
    e->input.auth_hash = auth_hash;
    e->input.nonce_caller = *nonce_caller;

    e->output.handle = handle;
    e->output.rc = rc;

    will_return(__wrap_Tss2_Sys_StartAuthSession, e);
}

static inline void set_expected_defaults(TPM2_SE session_type,
        TPMI_SH_AUTH_SESSION handle, TPM2_RC rc) {

    TPM2B_ENCRYPTED_SECRET encrypted_salt;
    memset(&encrypted_salt, 0, sizeof(encrypted_salt));

    TPMT_SYM_DEF symmetric;
    memset(&symmetric, 0, sizeof(symmetric));
    symmetric.algorithm = TPM2_ALG_NULL;

    TPM2B_NONCE nonce_caller;
    memset(&nonce_caller, 0, sizeof(nonce_caller));
    nonce_caller.size = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA1);

    set_expected(
    TPM2_RH_NULL,
    TPM2_RH_NULL, &encrypted_salt, session_type, &symmetric,
    TPM2_ALG_SHA256, &nonce_caller, handle, rc);
}

TSS2_RC __wrap_Tss2_Sys_StartAuthSession(TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT tpmKey, TPMI_DH_ENTITY bind,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPM2B_NONCE *nonceCaller,
        const TPM2B_ENCRYPTED_SECRET *encryptedSalt, TPM2_SE sessionType,
        const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
        TPMI_SH_AUTH_SESSION *sessionHandle, TPM2B_NONCE *nonceTPM,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {

    UNUSED(sysContext);
    UNUSED(cmdAuthsArray);
    UNUSED(nonceTPM);
    UNUSED(rspAuthsArray);

    expected_data *e = mock_ptr_type(expected_data *);

    assert_int_equal(tpmKey, e->input.key);

    assert_int_equal(bind, e->input.bind);

    assert_memory_equal(nonceCaller, &e->input.nonce_caller,
            sizeof(*nonceCaller));

    assert_memory_equal(encryptedSalt, &e->input.encrypted_salt,
            sizeof(*encryptedSalt));

    assert_int_equal(sessionType, e->input.session_type);

    assert_memory_equal(symmetric, &e->input.symmetric, sizeof(*symmetric));

    assert_int_equal(authHash, e->input.auth_hash);

    *sessionHandle = e->output.handle;

    TSS2_RC rc = e->output.rc;
    free(e);
    return rc;
}

TPMI_DH_CONTEXT _save_handle;

TSS2_RC __wrap_Tss2_Sys_ContextSave(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT saveHandle,
    TPMS_CONTEXT *context) {
    UNUSED(sysContext);
    UNUSED(context);

    _save_handle = saveHandle;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Tss2_Sys_ContextLoad(
    TSS2_SYS_CONTEXT *sysContext,
    const TPMS_CONTEXT *context,
    TPMI_DH_CONTEXT *loadedHandle) {

    UNUSED(sysContext);
    UNUSED(context);

    *loadedHandle = _save_handle;

    return TPM2_RC_SUCCESS;
}

static TSS2_RC policy_restart_return() {
    return (TSS2_RC)mock();
}

TSS2_RC __wrap_Tss2_Sys_PolicyRestart(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_SH_POLICY  sessionHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray
    ) {

    UNUSED(sysContext);
    UNUSED(sessionHandle);
    UNUSED(cmdAuthsArray);
    UNUSED(rspAuthsArray);

    return policy_restart_return();
}

#define SAPI_CONTEXT   ((TSS2_SYS_CONTEXT *)0xDEADBEEF)
#define SESSION_HANDLE 0xBADC0DE

static void test_tpm2_session_defaults_good(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
    assert_non_null(s);

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(s);
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

    TPM2B_ENCRYPTED_SECRET encsalt = {
            .size = 6,
            .secret = {
                'S', 'E', 'C', 'R', 'E', 'T'
            }
    };

    tpm2_session_set_encryptedsalt(d, &encsalt);

    tpm2_session_set_bind(d, 42);

    TPM2B_NONCE nonce = {
        .size = 5,
        .buffer = {
            'n', 'o', 'n', 'c', 'e'
        }
    };

    tpm2_session_set_nonce_caller(d, &nonce);

    tpm2_session_set_key(d, 0x1234);

    set_expected(0x1234, 42, &encsalt,
    TPM2_SE_TRIAL, &symmetric,
    TPM2_ALG_SHA512, &nonce,
    SESSION_HANDLE,
    TPM2_RC_SUCCESS);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
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

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
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

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
    assert_non_null(s);

    TPMI_SH_AUTH_SESSION handle1 = tpm2_session_get_handle(s);

    bool result = tpm2_session_save(SAPI_CONTEXT, s, (char *)*state);
    assert_true(result);

    tpm2_session_free(&s);
    assert_null(s);

    s = tpm2_session_restore(NULL, (char *)*state);
    assert_non_null(s);

    TPMI_SH_AUTH_SESSION handle2 = tpm2_session_get_handle(s);

    assert_int_equal(handle1, handle2);

    tpm2_session_free(&s);
    assert_null(s);
}

static void test_tpm2_session_restart(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
    assert_non_null(s);

    will_return(policy_restart_return, TPM2_RC_SUCCESS);
    bool result = tpm2_session_restart(SAPI_CONTEXT, s);
    assert_true(result);

    will_return(policy_restart_return, TPM2_RC_HANDLE);
    result = tpm2_session_restart(SAPI_CONTEXT, s);
    assert_false(result);

    tpm2_session_free(&s);
    assert_null(s);
}

static void test_tpm2_session_is_trial_test(void **state) {
    UNUSED(state);

    set_expected_defaults(TPM2_SE_TRIAL, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_TRIAL);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
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
