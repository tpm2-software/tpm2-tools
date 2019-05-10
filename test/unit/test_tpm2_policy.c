/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <tss2/tss2_esys.h>

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
 * Dummy value for the session handle read by the wrapped version of:
 *   Esys_StartAuthSession
 */
#define SESSION_HANDLE 0xDEADBEEF

/* dummy handle for esys context */
#define ESAPI_CONTEXT ((ESYS_CONTEXT *)0xDEADBEEF)

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

TSS2_RC __wrap_Esys_StartAuthSession(ESYS_CONTEXT *esysContext,
            ESYS_TR tpmKey, ESYS_TR bind,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
            const TPM2B_NONCE *nonceCaller, TPM2_SE sessionType,
            const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
            ESYS_TR *sessionHandle) {

    UNUSED(esysContext);
    UNUSED(tpmKey);
    UNUSED(bind);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(nonceCaller);
    UNUSED(sessionType);
    UNUSED(symmetric);
    UNUSED(authHash);

    *sessionHandle = SESSION_HANDLE;

    return TPM2_RC_SUCCESS;
}
/*
 * The current digest passed via PolicyPCR and
 * PolicyGetDigest.
 */
static TPM2B_DIGEST current_digest;

TSS2_RC __wrap_Esys_PolicyPCR(ESYS_CONTEXT *esysContext,
            ESYS_TR policySession,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
            const TPM2B_DIGEST *pcrDigest, const TPML_PCR_SELECTION *pcrs) {

    UNUSED(esysContext);
    UNUSED(policySession);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(pcrs);

    /*
     * Set the computed digest, which will be retrieved via
     * a call to Esys_PolicyGetDigest
     */
    current_digest = *pcrDigest;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_PolicyGetDigest(ESYS_CONTEXT *esysContext,
            ESYS_TR policySession,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
            TPM2B_DIGEST **policyDigest) {

    UNUSED(esysContext);
    UNUSED(policySession);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    *policyDigest = &current_digest;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_PCR_Read(ESYS_CONTEXT *esysContext,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
            const TPML_PCR_SELECTION *pcrSelectionIn, UINT32 *pcrUpdateCounter,
            TPML_PCR_SELECTION **pcrSelectionOut, TPML_DIGEST **pcrValues) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(pcrSelectionIn);
    UNUSED(pcrUpdateCounter);
    UNUSED(pcrSelectionOut);

    *pcrValues = calloc(1, sizeof(TPML_DIGEST));
    if (*pcrValues == NULL) {
        return TPM2_RC_FAILURE;
    }

    UINT32 i;
    /* NOTE: magic number of 4... The prior (SAPI) implementation had a
     * semi-populated pcrValues with an appropriate count value set.
     * This ESAPI call allocates the pcrValues out-value and thus we don't have
     * an appropriate count number at call time, therefore we hard-code the
     * expected value for the *one* call we're currently making in this unit
     * test.
     */
    for (i = 0; i < 4; i++) {
        (*pcrValues)->digests[i] = pcr_value;
    }

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_FlushContext(ESYS_CONTEXT *esysContext, ESYS_TR flushHandle) {
    UNUSED(esysContext);
    UNUSED(flushHandle);

    return TSS2_RC_SUCCESS;
}

static void test_tpm2_policy_build_pcr_good(void **state) {
    UNUSED(state);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_open(ESAPI_CONTEXT, d);
    assert_non_null(s);

    TPML_PCR_SELECTION pcr_selections;
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections);
    assert_true(res);

    bool result = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, NULL, &pcr_selections);
    assert_true(result);

    TPM2B_DIGEST *policy_digest;
    result = tpm2_policy_get_digest(ESAPI_CONTEXT, s, &policy_digest);
    assert_true(result);

    assert_int_equal(policy_digest->size, expected_policy_digest.size);
    assert_memory_equal(policy_digest->buffer, expected_policy_digest.buffer,
            expected_policy_digest.size);

    tpm2_session_close(&s);
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

    tpm2_session *s = tpm2_session_open(ESAPI_CONTEXT, d);
    assert_non_null(s);

    bool result = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, tf->path,
            &pcr_selections);
    assert_true(result);

    TPM2B_DIGEST *policy_digest;
    result = tpm2_policy_get_digest(ESAPI_CONTEXT, s, &policy_digest);
    assert_true(result);

    assert_int_equal(policy_digest->size, expected_policy_digest.size);
    assert_memory_equal(policy_digest->buffer, expected_policy_digest.buffer,
            expected_policy_digest.size);

    tpm2_session_close(&s);
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

    tpm2_session *s = tpm2_session_open(ESAPI_CONTEXT, d);
    assert_non_null(s);

    bool result = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, tf->path,
            &pcr_selections);
    tpm2_session_close(&s);
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
