/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_errata.h"
#include "tpm2_util.h"

static inline void setcaps(UINT32 level, UINT32 rev, UINT32 day, UINT32 year,
        TSS2_RC rc) {

    will_return(__wrap_Esys_GetCapability, level);
    will_return(__wrap_Esys_GetCapability, rev);
    will_return(__wrap_Esys_GetCapability, day);
    will_return(__wrap_Esys_GetCapability, year);
    will_return(__wrap_Esys_GetCapability, rc);

}

TSS2_RC __wrap_Esys_GetCapability(ESYS_CONTEXT *context, ESYS_TR session1,
        ESYS_TR session2, ESYS_TR session3, TPM2_CAP capability,
        UINT32 property, UINT32 propertyCount, TPMI_YES_NO *moreData,
        TPMS_CAPABILITY_DATA **capabilityData) {

    UNUSED(context);
    UNUSED(session1);
    UNUSED(session2);
    UNUSED(session3);
    UNUSED(property);
    UNUSED(propertyCount);

    /* Ensure moreData is TPM2_NO, otherwise tpm2_capability_get() will make
     * multiple calls to Esys_CapabilityGet()
     */
    *moreData = TPM2_NO;

    *capabilityData = calloc(1, sizeof(**capabilityData));
    (*capabilityData)->capability = capability;
    TPML_TAGGED_TPM_PROPERTY *properties =
            &(*capabilityData)->data.tpmProperties;

    properties->count = 4;

    properties->tpmProperty[0].property = TPM2_PT_LEVEL;
    properties->tpmProperty[0].value = (UINT32) mock();

    properties->tpmProperty[1].property = TPM2_PT_REVISION;
    properties->tpmProperty[1].value = (UINT32) mock();

    properties->tpmProperty[2].property = TPM2_PT_DAY_OF_YEAR;
    properties->tpmProperty[2].value = (UINT32) mock();

    properties->tpmProperty[3].property = TPM2_PT_YEAR;
    properties->tpmProperty[3].value = (UINT32) mock();

    TSS2_RC rc = (int) mock(); /* dequeue second value */
    if (rc != TSS2_RC_SUCCESS)
        free(*capabilityData);
    return rc;
}

#define TPM2B_PUBLIC_INIT(value) { \
    .publicArea = { \
        .objectAttributes = value \
    } \
}

static void test_tpm2_errata_no_init_and_apply(void **state) {
    UNUSED(state);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
            &in_public.publicArea.objectAttributes);

    assert_int_equal(
            in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
            TPMA_OBJECT_SIGN_ENCRYPT);
}

static void test_tpm2_errata_bad_init_and_apply(void **state) {
    UNUSED(state);

    setcaps(00, 116, 303, 2014, TPM2_RC_FAILURE);
    tpm2_errata_init((ESYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
            &in_public.publicArea.objectAttributes);

    assert_int_equal(
            in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
            TPMA_OBJECT_SIGN_ENCRYPT);
}

static void test_tpm2_errata_init_good_and_apply(void **state) {
    UNUSED(state);

    setcaps(00, 116, 303, 2014, TPM2_RC_SUCCESS);
    tpm2_errata_init((ESYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
            &in_public.publicArea.objectAttributes);

    assert_int_equal(
            in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
            0);
}

static void test_tpm2_errata_init_good_and_no_match(void **state) {
    UNUSED(state);

    setcaps(00, 116, 4, 2015, TPM2_RC_SUCCESS);
    //Tss2_Sys_GetCapability
    tpm2_errata_init((ESYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
            &in_public.publicArea.objectAttributes);

    assert_int_equal(
            in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
            TPMA_OBJECT_SIGN_ENCRYPT);
}

static void test_tpm2_errata_init_no_match_and_apply(void **state) {
    UNUSED(state);

    /* This will never match */
    setcaps(00, 00, 00, 00, TPM2_RC_SUCCESS);
    //Tss2_Sys_GetCapability
    tpm2_errata_init((ESYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
            &in_public.publicArea.objectAttributes);

    assert_int_equal(
            in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
            TPMA_OBJECT_SIGN_ENCRYPT);
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
        cmocka_unit_test(test_tpm2_errata_no_init_and_apply),
        cmocka_unit_test(test_tpm2_errata_bad_init_and_apply),
        cmocka_unit_test(test_tpm2_errata_init_good_and_apply),
        cmocka_unit_test(test_tpm2_errata_init_good_and_no_match),
        cmocka_unit_test(test_tpm2_errata_init_no_match_and_apply),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
