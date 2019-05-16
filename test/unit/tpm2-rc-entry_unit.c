//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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

#include "rc-decode.h"

/* Lookup an error code using the provided function. Assert that the returned
 * id matches the one that we looked up.
 *   tpm_rc: TSS2_RC we're looking up
 *   lookup_func: function to lookup the TSS2_RC
 */
#define LOOKUP_SUCCESS(tpm_rc, lookup_func) \
    LOOKUP_EXPECTED_SUCCESS (tpm_rc, tpm_rc, lookup_func);
/* Same as LOOKUP_SUCCESS but expect a failure.
 */
#define LOOKUP_FAILURE(tpm_rc, lookup_func) \
    TSS2_RC rc = (tpm_rc); \
    tpm2_rc_entry_t *entry = NULL; \
    entry = (lookup_func)(rc); \
    assert_null (entry);
/* Lookup TSS2_RC and compare to expected value. Assert success condition.
 *   tpm_rc: TSS2_RC we're looking up
 *   layer:  expected layer
 *   lookup_func: function to lookup the layer from the provided TSS2_RC
 */
#define LOOKUP_EXPECTED_SUCCESS(rc_in, rc_expect, lookup_func) \
    TSS2_RC rc = (rc_in); \
    tpm2_rc_entry_t *entry = NULL; \
    entry = (lookup_func)(rc); \
    assert_non_null (entry); \
    assert_int_equal ((rc_expect), entry->id);
/* Check for match in tpm2_tss_base_rc_entry table. */
static void
tpm2_rc_entry_tss_base_rc_general (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TSS2_BASE_RC_GENERAL_FAILURE, tpm2_get_tss_base_rc_entry);
}
static void
tpm2_rc_entry_tss_base_rc_insufficient_buffer (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TSS2_BASE_RC_INSUFFICIENT_BUFFER, tpm2_get_tss_base_rc_entry);
}
/* Check for non-existant error codes in the tpm2_tss_base_rc_entry table */
static void
tpm2_rc_entry_tss_base_rc_bad_min (void **state)
{
    (void) state;
    LOOKUP_FAILURE (0x0, tpm2_get_tss_base_rc_entry);
}
static void
tpm2_rc_entry_tss_base_rc_bad_max (void **state)
{
    (void) state;
    LOOKUP_FAILURE (0xffff, tpm2_get_tss_base_rc_entry);
}
/* Check for match in tpm2_tss_base_rc_entry with TCTI layer indicator set */
static void
tpm2_rc_entry_tss_tcti_rc_general (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_TCTI_RC_INSUFFICIENT_BUFFER,
                             TSS2_BASE_RC_INSUFFICIENT_BUFFER,
                             tpm2_get_tss_base_rc_entry);
}

/* Check for match in tpm2_tss_base_rc_entry with SAPI (aka SYS) layer set */
static void
tpm2_rc_entry_tss_sapi_rc_bad_value (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_SYS_RC_BAD_VALUE,
                             TSS2_BASE_RC_BAD_VALUE,
                             tpm2_get_tss_base_rc_entry);
}
/* Check for match in tpm2_position_entry for the first parameter indicator.
 * NOTE: The parameter indicator is ignored. In reality this should be checked
 * first.
 */
static void
tpm2_rc_entry_parameter_1 (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TPM2_RC_P + TPM2_RC_1,
                             TPM2_RC_1,
                             tpm2_get_parameter_entry);
}
static void
tpm2_rc_entry_parameter_a (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TPM2_RC_P + TPM2_RC_A,
                             TPM2_RC_A,
                             tpm2_get_parameter_entry);
}
/* same for tpm2_handle_entry */
static void
tpm2_rc_entry_handle_3 (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TPM2_RC_H + TPM2_RC_3,
                             TPM2_RC_3,
                             tpm2_get_handle_entry);
}
static void
tpm2_rc_entry_handle_7 (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TPM2_RC_H + TPM2_RC_7,
                             TPM2_RC_7,
                             tpm2_get_handle_entry);
}
/* same for tpm2_session_entry */
static void
tpm2_rc_entry_session_2 (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TPM2_RC_H + TPM2_RC_2,
                             TPM2_RC_2,
                             tpm2_get_session_entry);
}
static void
tpm2_rc_entry_session_5 (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TPM2_RC_H + TPM2_RC_5,
                             TPM2_RC_5,
                             tpm2_get_session_entry);
}
/* Check for match in tpm2_tss_layer_entry for the TCTI layer. */
static void
tpm2_rc_entry_layer_tcti_from_general_failure (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_TCTI_RC_GENERAL_FAILURE,
                             TSS2_TCTI_RC_LAYER,
                             tpm2_get_layer_entry);
}
static void
tpm2_rc_entry_layer_tcti_from_not_permitted (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_TCTI_RC_NOT_PERMITTED,
                             TSS2_TCTI_RC_LAYER,
                             tpm2_get_layer_entry);
}
/* Check for match in tpm2_tss_layer_entry for the SAPI (aka SYS) layer */
static void
tpm2_rc_entry_layer_sapi_from_no_encrypt_param (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_SYS_RC_NO_ENCRYPT_PARAM,
                             TSS2_SYS_RC_LAYER,
                             tpm2_get_layer_entry);
}
static void
tpm2_rc_entry_layer_sapi_from_bad_tcti_structure (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_SYS_RC_BAD_TCTI_STRUCTURE,
                             TSS2_SYS_RC_LAYER,
                             tpm2_get_layer_entry);
}
/* Part2 error messages generated by SAPI as part of offloading the error
 * checking.
 */
static void
tpm2_rc_entry_layer_part2_from_all (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_MU_RC_LAYER | ~(0xff << TSS2_RC_LAYER_SHIFT),
                             TSS2_MU_RC_LAYER,
                             tpm2_get_layer_entry);
}
/* Lookup layer to identify errors from the TPM */
static void
tpm2_rc_entry_layer_tpm (void **state)
{
    (void) state;
    LOOKUP_EXPECTED_SUCCESS (TSS2_TPM_RC_LAYER | ~(0xff << TSS2_RC_LAYER_SHIFT),
            TSS2_TPM_RC_LAYER, tpm2_get_layer_entry);
}
/* Lookup non-existant error level */
static void
tpm2_rc_entry_layer_bad (void **state)
{
    (void) state;
    LOOKUP_FAILURE (~(0x1 << TSS2_RC_LAYER_SHIFT), tpm2_get_layer_entry);
}
/* Lookup structures holding data about format0 / VER1 error codes.
 */
static void
tpm2_rc_entry_fmt0_failure (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TPM2_RC_FAILURE, tpm2_get_fmt0_entry);
}
static void
tpm2_rc_entry_fmt0_pcr_changed (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TPM2_RC_PCR_CHANGED, tpm2_get_fmt0_entry);
}
/* Check for no match on invalid fmt0 / ver1 error code */
static void
tpm2_rc_entry_fmt0_bad (void **state)
{
    (void) state;
    LOOKUP_FAILURE (0x023, tpm2_get_fmt0_entry);
}
/* Lookup structures holding data about format1 / FMT1 error codes.
 */
static void
tpm2_rc_entry_fmt1_hierarchy (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TPM2_RC_HIERARCHY, tpm2_get_fmt1_entry);
}
static void
tpm2_rc_entry_fmt1_expired (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TPM2_RC_EXPIRED, tpm2_get_fmt1_entry);
}
static void
tpm2_rc_entry_fmt1_bad (void **state)
{
    (void) state;
    LOOKUP_FAILURE (0x30, tpm2_get_fmt1_entry);
}
/* Lookup structures holding data about fmt1 warning error codes.
 */
static void
tpm2_rc_entry_warn_memory (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TPM2_RC_MEMORY, tpm2_get_warn_entry);
}
static void
tpm2_rc_entry_warn_reference_s5 (void **state)
{
    (void) state;
    LOOKUP_SUCCESS (TPM2_RC_REFERENCE_S5, tpm2_get_warn_entry);
}
static void
tpm2_rc_entry_warn_bad (void **state)
{
    (void) state;
    LOOKUP_FAILURE (0x17, tpm2_get_warn_entry);
}
/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;
int
main (int   argc,
      char *argv[])
{
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tpm2_rc_entry_tss_base_rc_general),
        cmocka_unit_test (tpm2_rc_entry_tss_base_rc_insufficient_buffer),
        cmocka_unit_test (tpm2_rc_entry_tss_base_rc_bad_min),
        cmocka_unit_test (tpm2_rc_entry_tss_base_rc_bad_max),
        cmocka_unit_test (tpm2_rc_entry_tss_tcti_rc_general),
        cmocka_unit_test (tpm2_rc_entry_tss_sapi_rc_bad_value),
        cmocka_unit_test (tpm2_rc_entry_parameter_1),
        cmocka_unit_test (tpm2_rc_entry_parameter_a),
        cmocka_unit_test (tpm2_rc_entry_handle_3),
        cmocka_unit_test (tpm2_rc_entry_handle_7),
        cmocka_unit_test (tpm2_rc_entry_session_2),
        cmocka_unit_test (tpm2_rc_entry_session_5),
        cmocka_unit_test (tpm2_rc_entry_layer_tcti_from_general_failure),
        cmocka_unit_test (tpm2_rc_entry_layer_tcti_from_not_permitted),
        cmocka_unit_test (tpm2_rc_entry_layer_sapi_from_no_encrypt_param),
        cmocka_unit_test (tpm2_rc_entry_layer_sapi_from_bad_tcti_structure),
        cmocka_unit_test (tpm2_rc_entry_layer_part2_from_all),
        cmocka_unit_test (tpm2_rc_entry_layer_tpm),
        cmocka_unit_test (tpm2_rc_entry_layer_bad),
        cmocka_unit_test (tpm2_rc_entry_fmt0_failure),
        cmocka_unit_test (tpm2_rc_entry_fmt0_pcr_changed),
        cmocka_unit_test (tpm2_rc_entry_fmt0_bad),
        cmocka_unit_test (tpm2_rc_entry_fmt1_hierarchy),
        cmocka_unit_test (tpm2_rc_entry_fmt1_expired),
        cmocka_unit_test (tpm2_rc_entry_fmt1_bad),
        cmocka_unit_test (tpm2_rc_entry_warn_memory),
        cmocka_unit_test (tpm2_rc_entry_warn_reference_s5),
        cmocka_unit_test (tpm2_rc_entry_warn_bad),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
