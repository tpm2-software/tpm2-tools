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

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "tpm2_errata.h"
#include "tpm2_util.h"

static inline void setcaps(UINT32 level, UINT32 rev, UINT32 day, UINT32 year, TSS2_RC rc) {

    will_return(__wrap_Tss2_Sys_GetCapability, level);
    will_return(__wrap_Tss2_Sys_GetCapability, rev);
    will_return(__wrap_Tss2_Sys_GetCapability, day);
    will_return(__wrap_Tss2_Sys_GetCapability, year);
    will_return(__wrap_Tss2_Sys_GetCapability, rc);

}

TSS2_RC __wrap_Tss2_Sys_GetCapability(TSS2_SYS_CONTEXT *sysContext,
        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray, TPM2_CAP capability,
        UINT32 property, UINT32 propertyCount, TPMI_YES_NO *moreData,
        TPMS_CAPABILITY_DATA *capabilityData, TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {

    UNUSED(sysContext);
    UNUSED(cmdAuthsArray);
    UNUSED(capability);
    UNUSED(property);
    UNUSED(propertyCount);
    UNUSED(moreData);
    UNUSED(capabilityData);
    UNUSED(rspAuthsArray);

    TPML_TAGGED_TPM_PROPERTY *properties = &capabilityData->data.tpmProperties;

    properties->count = 4;

    properties->tpmProperty[0].property = TPM2_PT_LEVEL;
    properties->tpmProperty[0].value    = (UINT32) mock();

    properties->tpmProperty[1].property = TPM2_PT_REVISION;
    properties->tpmProperty[1].value    = (UINT32) mock();

    properties->tpmProperty[2].property = TPM2_PT_DAY_OF_YEAR;
    properties->tpmProperty[2].value    = (UINT32) mock();

    properties->tpmProperty[3].property = TPM2_PT_YEAR;
    properties->tpmProperty[3].value    = (UINT32) mock();

    return (int) mock(); /* dequeue second value */
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

    assert_int_equal(in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
                    TPMA_OBJECT_SIGN_ENCRYPT);
}

static void test_tpm2_errata_bad_init_and_apply(void **state) {
    UNUSED(state);

    setcaps(00, 116, 303, 2014, TPM2_RC_FAILURE);
    tpm2_errata_init((TSS2_SYS_CONTEXT *) 0xDEADBEEF);


    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &in_public.publicArea.objectAttributes);

    assert_int_equal(in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
                    TPMA_OBJECT_SIGN_ENCRYPT);
}

static void test_tpm2_errata_init_good_and_apply(void **state) {
    UNUSED(state);

    setcaps(00, 116, 303, 2014, TPM2_RC_SUCCESS);
    tpm2_errata_init((TSS2_SYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &in_public.publicArea.objectAttributes);

    assert_int_equal(in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
                     0);
}

static void test_tpm2_errata_init_good_and_no_match(void **state) {
    UNUSED(state);

    setcaps(00, 116, 4, 2015, TPM2_RC_SUCCESS);
    //Tss2_Sys_GetCapability
    tpm2_errata_init((TSS2_SYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &in_public.publicArea.objectAttributes);

    assert_int_equal(in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
                    TPMA_OBJECT_SIGN_ENCRYPT);
}

static void test_tpm2_errata_init_no_match_and_apply(void **state) {
    UNUSED(state);

    /* This will never match */
    setcaps(00, 00, 00, 00, TPM2_RC_SUCCESS);
    //Tss2_Sys_GetCapability
    tpm2_errata_init((TSS2_SYS_CONTEXT *) 0xDEADBEEF);

    TPM2B_PUBLIC in_public = TPM2B_PUBLIC_INIT(TPMA_OBJECT_SIGN_ENCRYPT);

    tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                      &in_public.publicArea.objectAttributes);

    assert_int_equal(in_public.publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT,
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
