/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "pcr.h"
#include "tpm2_policy.h"
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
#define PCR_SEL_SPEC_FWD "sha256:0,1=96a7faaf1609b650a4f288c0904f04836ecada2f4978069486a2bb02f2f043ea,2,3=96a7faaf1609b650a4f288c0904f04836ecada2f4978069486a2bb02f2f043ea"

/*
 * Dummy value for the session handle read by the wrapped version of:
 *   Esys_StartAuthSession
 */
#define SESSION_HANDLE 0xDEADBEEF

/* dummy handle for esys context */
#define ESAPI_CONTEXT ((ESYS_CONTEXT *)0xDEADBEEF)

/* PCR read returns this value - except for forward seal. */
static TPM2B_DIGEST pcr_value = {
        .size = 32,
        .buffer = {
            0x96, 0xa7, 0xfa, 0xaf, 0x16, 0x09, 0xb6, 0x50, 0xa4, 0xf2,
            0x88, 0xc0, 0x90, 0x4f, 0x04, 0x83, 0x6e, 0xca, 0xda, 0x2f,
            0x49, 0x78, 0x06, 0x94, 0x86, 0xa2, 0xbb, 0x02, 0xf2, 0xf0,
            0x43, 0xea
        }
};

/* Forward seal value to read for odd-numbered PCRs.  These need to be
 * overridden with forward seal values matchin pcr_value above. */
static TPM2B_DIGEST pcr_value_odd = {
        .size = 32,
        .buffer = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
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

/* fake sha256 digests */
static const UINT8 sha256_digest[32] =  {
    0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7,
    0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12,
    0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c
};

static const UINT8 sha256_digest_2[32] =  {
    0x7d, 0x86, 0x5e, 0x95, 0x9b, 0x24, 0x66, 0x91, 0x8c, 0x98, 0x63, 0xaf,
    0xca, 0x94, 0x2d, 0x0f, 0xb8, 0x9d, 0x7c, 0x9a, 0xc0, 0xc9, 0x9b, 0xaf,
    0xc3, 0x74, 0x95, 0x04, 0xde, 0xd9, 0x77, 0x30
};

static const UINT8 *current_sha256_digest = sha256_digest;

TSS2_RC __wrap_Esys_StartAuthSession(ESYS_CONTEXT *esysContext, ESYS_TR tpmKey,
        ESYS_TR bind, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
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

TSS2_RC __wrap_Esys_PolicyPCR(ESYS_CONTEXT *esysContext, ESYS_TR policySession,
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
        ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2,
        ESYS_TR shandle3, TPM2B_DIGEST **policyDigest) {

    UNUSED(esysContext);
    UNUSED(policySession);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    *policyDigest = &current_digest;

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_PCR_Read(ESYS_CONTEXT *esysContext, ESYS_TR shandle1,
        ESYS_TR shandle2, ESYS_TR shandle3,
        const TPML_PCR_SELECTION *pcrSelectionIn, UINT32 *pcrUpdateCounter,
        TPML_PCR_SELECTION **pcrSelectionOut, TPML_DIGEST **pcrValues) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(pcrUpdateCounter);

    *pcrValues = calloc(1, sizeof(TPML_DIGEST));
    if (*pcrValues == NULL) {
        return TPM2_RC_FAILURE;
    }

    if (pcrSelectionOut) {
        *pcrSelectionOut = calloc(1, sizeof(**pcrSelectionOut));
        if (*pcrSelectionOut == NULL) {
            return TPM2_RC_FAILURE;
        }
        //memcpy(*pcrSelectionOut, pcrSelectionIn, sizeof(**pcrSelectionOut));
        (*pcrSelectionOut)->pcrSelections[0].sizeofSelect =
            pcrSelectionIn->pcrSelections[0].sizeofSelect;
        (*pcrSelectionOut)->pcrSelections[0].hash =
            pcrSelectionIn->pcrSelections[0].hash;
        (*pcrSelectionOut)->count = 1;
    }

    UINT32 i;
    UINT32 pcr;
    /* NOTE: magic number of 4... The prior (SAPI) implementation had a
     * semi-populated pcrValues with an appropriate count value set.
     * This ESAPI call allocates the pcrValues out-value and thus we don't have
     * an appropriate count number at call time, therefore we hard-code the
     * expected value for the *one* call we're currently making in this unit
     * test.
     */
    for (i = 0, pcr = 0;
         pcr < pcrSelectionIn->pcrSelections[0].sizeofSelect * 8;
         pcr++) {
        if (!tpm2_util_is_pcr_select_bit_set(&pcrSelectionIn->pcrSelections[0],
                                             pcr))
            continue;

        (*pcrValues)->digests[i] = pcr_value;
        (*pcrValues)->count++;
        i++;
        if (pcrSelectionOut) {
            (*pcrSelectionOut)->pcrSelections[0].pcrSelect[pcr / 8] |=
                (1 << (pcr % 8));
        }

        if (i == ARRAY_LEN((*pcrValues)->digests))
            break;
    }

    return TPM2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_FlushContext(ESYS_CONTEXT *esysContext, ESYS_TR flushHandle) {
    UNUSED(esysContext);
    UNUSED(flushHandle);

    return TSS2_RC_SUCCESS;
}

bool __real_files_get_file_size_path(const char *path, unsigned long *file_size);
bool __wrap_files_get_file_size_path(const char *path, unsigned long *file_size) {

    if (strcmp(path, "testpolicy.sha256")) {
        return __real_files_get_file_size_path(path, file_size);
    }

    *file_size = 32;
    return true;
}

bool __real_files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size);
bool __wrap_files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {

    if (strcmp(path, "testpolicy.sha256")) {
        return __real_files_load_bytes_from_path(path, buf, size);
    }

    /* plop in a fake digest */
    *size = 32;
    memcpy(buf, current_sha256_digest, 32);

    return true;
}


static void test_tpm2_policy_build_pcr_good(void **state) {
    UNUSED(state);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = NULL;
    tool_rc rc = tpm2_session_open(ESAPI_CONTEXT, d, &s);
    assert_int_equal(rc, tool_rc_success);
    assert_non_null(s);

    TPML_PCR_SELECTION pcr_selections;
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections, NULL);
    assert_true(res);

    rc = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, NULL, &pcr_selections, NULL,
        NULL);
    assert_int_equal(rc, tool_rc_success);

    TPM2B_DIGEST *policy_digest;
    rc = tpm2_policy_get_digest(ESAPI_CONTEXT, s, &policy_digest, 0,
        TPM2_ALG_ERROR);
    assert_int_equal(rc, tool_rc_success);

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

    tf->path = strdup("xxx_test_tpm2_policy_xxx.test");
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
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections, NULL);
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

    tpm2_session *s = NULL;
    tool_rc trc = tpm2_session_open(ESAPI_CONTEXT, d, &s);
    assert_int_equal(trc, tool_rc_success);
    assert_non_null(s);

    trc = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, tf->path, &pcr_selections,
        NULL, NULL);
    assert_int_equal(trc, tool_rc_success);

    TPM2B_DIGEST *policy_digest;
    trc = tpm2_policy_get_digest(ESAPI_CONTEXT, s, &policy_digest, 0,
        TPM2_ALG_ERROR);
    assert_int_equal(rc, tool_rc_success);

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
    bool res = pcr_parse_selections(PCR_SEL_SPEC, &pcr_selections, NULL);
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

    tpm2_session *s = NULL;
    tool_rc trc = tpm2_session_open(ESAPI_CONTEXT, d, &s);
    assert_int_equal(trc, tool_rc_success);
    assert_non_null(s);

    trc = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, tf->path, &pcr_selections,
        NULL, NULL);
    tpm2_session_close(&s);
    assert_null(s);
    assert_int_equal(trc, tool_rc_general_error);
}

/*
 * Test forward sealing.  The idea is here to re-use the existing expected test
 * results.  To test the forward sealing, pcr_value_odd is written for the
 * odd-numbered PCRs and this must be overridden with the expected pcr_value by
 * the forward sealing value.
 */
static void test_tpm2_policy_build_pcr_forward_good(void **state) {

    test_file *tf = test_file_from_state(state);
    assert_non_null(tf);

    tpm2_forwards forwards = {};

    /*
     * This PCR selection must not be to big too fit in the selection
     * array at index 0 byte index 0.
     *
     * If it is, the file generation below needs to change.
     */
    TPML_PCR_SELECTION pcr_selections;
    bool res = pcr_parse_selections(PCR_SEL_SPEC_FWD, &pcr_selections,
                                    &forwards);
    assert_true(res);

    /*
     * Create a file with the expected PCR hashes based on the number of pcr
     * selections. We know that the PCR selection above will always be in the
     * first selection array in the first byte.
     */
    UINT32 i;
    UINT32 cnt = tpm2_util_pop_count(
            pcr_selections.pcrSelections[0].pcrSelect[0]);

    for (i = 0; i < cnt; i++) {
        TPM2B_DIGEST *d;
        if (i & 1)
            d = &pcr_value_odd;
        else
            d = &pcr_value;

        size_t num = fwrite(d->buffer, d->size, 1, tf->file);
        assert_int_equal(num, 1);
    }

    int rc = fflush(tf->file);
    assert_int_equal(rc, 0);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = NULL;
    tool_rc trc = tpm2_session_open(ESAPI_CONTEXT, d, &s);
    assert_int_equal(trc, tool_rc_success);
    assert_non_null(s);

    trc = tpm2_policy_build_pcr(ESAPI_CONTEXT, s, tf->path, &pcr_selections,
        NULL, &forwards);
    assert_int_equal(trc, tool_rc_success);

    TPM2B_DIGEST *policy_digest;
    trc = tpm2_policy_get_digest(ESAPI_CONTEXT, s, &policy_digest, 0,
        TPM2_ALG_ERROR);
    assert_int_equal(rc, tool_rc_success);

    assert_int_equal(policy_digest->size, expected_policy_digest.size);
    assert_memory_equal(policy_digest->buffer, expected_policy_digest.buffer,
            expected_policy_digest.size);

    tpm2_session_close(&s);
    assert_null(s);
}

static void tpm2_policy_parse_policy_list_good(void **state) {
    UNUSED(state);

    TPML_DIGEST policy_list = { 0 };
    char str[] = "sha256:testpolicy.sha256,testpolicy.sha256";
    bool res = tpm2_policy_parse_policy_list(str, &policy_list);
    assert_true(res);
    assert_int_equal(policy_list.count, 2);
    assert_int_equal(policy_list.digests[0].size, sizeof(sha256_digest));
    assert_memory_equal(policy_list.digests[0].buffer, sha256_digest, sizeof(sha256_digest));
    assert_int_equal(policy_list.digests[1].size, sizeof(sha256_digest));
    assert_memory_equal(policy_list.digests[1].buffer, sha256_digest, sizeof(sha256_digest));
}

static void tpm2_policy_parse_policy_list_double_call(void **state) {
    UNUSED(state);

    TPML_DIGEST policy_list = { 0 };
    char str[] = "sha256:testpolicy.sha256,testpolicy.sha256";
    bool res = tpm2_policy_parse_policy_list(str, &policy_list);
    assert_true(res);
    assert_int_equal(policy_list.count, 2);
    assert_int_equal(policy_list.digests[0].size, sizeof(sha256_digest));
    assert_memory_equal(policy_list.digests[0].buffer, sha256_digest, sizeof(sha256_digest));
    assert_int_equal(policy_list.digests[1].size, sizeof(sha256_digest));
    assert_memory_equal(policy_list.digests[1].buffer, sha256_digest, sizeof(sha256_digest));

    /* swap digests to ensure we know where we wrote to in the array */
    current_sha256_digest = sha256_digest_2;

    /* strtok_r in previous calls modifies this */
    char str2[] = "sha256:testpolicy.sha256,testpolicy.sha256";
    res = tpm2_policy_parse_policy_list(str2, &policy_list);
    assert_true(res);
    /* count should go to 4 */
    assert_int_equal(policy_list.count, 4);

    /* original data intact */
    assert_int_equal(policy_list.digests[0].size, sizeof(sha256_digest));
    assert_memory_equal(policy_list.digests[0].buffer, sha256_digest, sizeof(sha256_digest));
    assert_int_equal(policy_list.digests[1].size, sizeof(sha256_digest));
    assert_memory_equal(policy_list.digests[1].buffer, sha256_digest, sizeof(sha256_digest));

    /* extra data */
    assert_int_equal(policy_list.digests[2].size, sizeof(sha256_digest_2));
    assert_memory_equal(policy_list.digests[2].buffer, sha256_digest_2, sizeof(sha256_digest_2));
    assert_int_equal(policy_list.digests[3].size, sizeof(sha256_digest_2));
    assert_memory_equal(policy_list.digests[3].buffer, sha256_digest_2, sizeof(sha256_digest_2));
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
        cmocka_unit_test(tpm2_policy_parse_policy_list_good),
        cmocka_unit_test(tpm2_policy_parse_policy_list_double_call),
        cmocka_unit_test_setup_teardown(test_tpm2_policy_build_pcr_file_good,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_tpm2_policy_build_pcr_file_bad_size,
                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_tpm2_policy_build_pcr_forward_good,
                test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
