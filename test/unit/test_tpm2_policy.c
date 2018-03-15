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
#include <stdarg.h>
#include <stddef.h>

#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include <tss2/tpm20.h>

#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct pcr_data pcr_data;
struct pcr_data {
    TPML_DIGEST values;
};

typedef struct test_file test_file;
struct test_file {
    char *path;
    FILE *file;
};

/* Passing tests and static data are hardcoded around this sel spec */
#define PCR_SEL_SPEC "sha256:0,1,2,3"

/*
 * Dummy value for the session handle read by teh wrapped version of:
 *   Tss2_Sys_StartAuthSession
 */
#define SESSION_HANDLE 0xDEADBEEF

/* dummy handle for sapi context */
#define SAPI_CONTEXT   ((TSS2_SYS_CONTEXT *)0xDEADBEEF)

/* Any PCR read returns this value */
static TPM2B_DIGEST pcr_value = {
        .size = 32,
        .buffer = {
            0x96, 0xa7, 0xfa, 0xaf, 0x16, 0x09, 0xb6, 0x50, 0xa4, 0xf2,
            0x88, 0xc0, 0x90, 0x4f, 0x04, 0x83, 0x6e, 0xca, 0xda, 0x2f,
            0x49, 0x78, 0x06, 0x94, 0x86, 0xa2, 0xbb, 0x02, 0xf2, 0xf0,
            0x43, 0xea
        }
};

/* The expected hash for the pcr selection of sha256:0,1,2,3 */
static TPM2B_DIGEST expected_policy_digest = {
        .size = 32,
        .buffer = {
            0x62, 0x69, 0x69, 0xce, 0xa7, 0xc2, 0xea, 0x7a, 0xf8, 0x86,
            0xf4, 0xb5, 0x09, 0xa5, 0xb8, 0x3a, 0xb3, 0x3b, 0x3a, 0x75,
            0x75, 0x5d, 0x17, 0x40, 0x38, 0xa8, 0xd3, 0x33, 0x0f, 0xa7,
            0x2a, 0xd4
        }
};

TSS2_RC __wrap_Tss2_Sys_StartAuthSession(TSS2_SYS_CONTEXT *sysContext,
        TPMI_DH_OBJECT tpmKey, TPMI_DH_ENTITY bind,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPM2B_NONCE *nonceCaller,
        const TPM2B_ENCRYPTED_SECRET *encryptedSalt, TPM2_SE sessionType,
        const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
        TPMI_SH_AUTH_SESSION *sessionHandle, TPM2B_NONCE *nonceTPM,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {

    UNUSED(sysContext);
    UNUSED(tpmKey);
    UNUSED(bind);
    UNUSED(cmdAuthsArray);
    UNUSED(nonceCaller);
    UNUSED(encryptedSalt);
    UNUSED(sessionType);
    UNUSED(symmetric);
    UNUSED(authHash);
    UNUSED(nonceTPM);
    UNUSED(rspAuthsArray);

    *sessionHandle = SESSION_HANDLE;

    return TPM2_RC_SUCCESS;
}

/*
 * The current digest passed via PolicyPCR and
 * PolicyGetDigest.
 */
static TPM2B_DIGEST current_digest;

TSS2_RC __wrap_Tss2_Sys_PolicyPCR(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_SH_POLICY policySession,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPM2B_DIGEST *pcrDigest,
        const TPML_PCR_SELECTION *pcrs,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {

    UNUSED(sysContext);
    UNUSED(policySession);
    UNUSED(cmdAuthsArray);
    UNUSED(pcrs);
    UNUSED(rspAuthsArray);

    /*
     * Set the computed digest, which will be retrieved via
     * a call to Tss2_Sys_PolicyGetDigest
     */
    current_digest = *pcrDigest;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Tss2_Sys_PolicyGetDigest(
        TSS2_SYS_CONTEXT *sysContext,
        TPMI_SH_POLICY policySession,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        TPM2B_DIGEST *policyDigest,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {

    UNUSED(sysContext);
    UNUSED(policySession);
    UNUSED(cmdAuthsArray);
    UNUSED(rspAuthsArray);

    *policyDigest = current_digest;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Tss2_Sys_PCR_Read(
        TSS2_SYS_CONTEXT *sysContext,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
        const TPML_PCR_SELECTION *pcrSelectionIn, UINT32 *pcrUpdateCounter,
        TPML_PCR_SELECTION *pcrSelectionOut, TPML_DIGEST *pcrValues,
        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {

    UNUSED(sysContext);
    UNUSED(pcrSelectionIn);
    UNUSED(pcrUpdateCounter);
    UNUSED(pcrSelectionOut);
    UNUSED(cmdAuthsArray);
    UNUSED(rspAuthsArray);

    UINT32 i;
    for (i = 0; i < pcrValues->count; i++) {
        pcrValues->digests[i] = pcr_value;
    }

    return TPM2_RC_SUCCESS;
}

static void test_tpm2_policy_build_pcr_good(void **state) {
    UNUSED(state);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
    assert_non_null(s);

    TPML_PCR_SELECTION pcr_selections;
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections);
    assert_true(res);

    bool result = tpm2_policy_build_pcr(SAPI_CONTEXT, s, NULL, &pcr_selections);
    assert_true(result);

    TPM2B_DIGEST policy_digest;
    result = tpm2_policy_get_digest(SAPI_CONTEXT, s, &policy_digest);
    assert_true(result);

    assert_int_equal(policy_digest.size, expected_policy_digest.size);
    assert_memory_equal(policy_digest.buffer, expected_policy_digest.buffer,
            expected_policy_digest.size);

    tpm2_session_free(&s);
    assert_null(s);
}

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

static void test_tpm2_policy_build_pcr_file_good(void **state) {

    test_file *tf = test_file_from_state(state);
    assert_non_null(tf);

    /*
     * This PCR selection must not be to big to fit in the selection
     * array at index 0 byte index 0.
     *
     * If it is, the file generation below needs to change.
     */
    TPML_PCR_SELECTION pcr_selections;
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections);
    assert_true(res);

    /*
     * create a file with the expected PCR hashes based on the number of pcr
     * selections. We know that the PCR selection above will always be in the
     * first selection array in the first byte.
     */
    UINT32 i;
    UINT32 cnt = tpm2_util_pop_count(
            pcr_selections.pcrSelections[0].pcrSelect[0]);

    for (i = 0; i < cnt; i++) {
        TPM2B_DIGEST *d = &pcr_value;
        size_t num = fwrite(d->buffer, d->size, 1, tf->file);
        assert_int_equal(num, 1);
    }

    int rc = fflush(tf->file);
    assert_int_equal(rc, 0);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
    assert_non_null(s);

    bool result = tpm2_policy_build_pcr(SAPI_CONTEXT, s, tf->path,
            &pcr_selections);
    assert_true(result);

    TPM2B_DIGEST policy_digest;
    result = tpm2_policy_get_digest(SAPI_CONTEXT, s, &policy_digest);
    assert_true(result);

    assert_int_equal(policy_digest.size, expected_policy_digest.size);
    assert_memory_equal(policy_digest.buffer, expected_policy_digest.buffer,
            expected_policy_digest.size);

    tpm2_session_free(&s);
    assert_null(s);
}

static void test_tpm2_policy_build_pcr_file_bad_size(void **state) {

    test_file *tf = test_file_from_state(state);
    assert_non_null(tf);

    /*
     * This PCR selection must not be to big to fit in the selection
     * array at index 0 byte index 0.
     *
     * If it is, the file generation below needs to change.
     */
    TPML_PCR_SELECTION pcr_selections;
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections);
    assert_true(res);

    /*
     * create a file with the expected PCR hashes based on the number of pcr
     * selections. We know that the PCR selection above will always be in the
     * first selection array in the first byte.
     */
    UINT32 i;
    /* force the size to be bad here by subtracting 1 */
    UINT32 cnt = tpm2_util_pop_count(
            pcr_selections.pcrSelections[0].pcrSelect[0]) - 1;

    for (i = 0; i < cnt; i++) {
        TPM2B_DIGEST *d = &pcr_value;
        size_t num = fwrite(d->buffer, d->size, 1, tf->file);
        assert_int_equal(num, 1);
    }

    int rc = fflush(tf->file);
    assert_int_equal(rc, 0);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(SAPI_CONTEXT, d);
    assert_non_null(s);

    bool result = tpm2_policy_build_pcr(SAPI_CONTEXT, s, tf->path,
            &pcr_selections);
    tpm2_session_free(&s);
    assert_null(s);
    assert_false(result);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tpm2_policy_build_pcr_good),
        cmocka_unit_test_setup_teardown(test_tpm2_policy_build_pcr_file_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_tpm2_policy_build_pcr_file_bad_size,
                test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
