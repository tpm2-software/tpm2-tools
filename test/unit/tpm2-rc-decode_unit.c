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

#define TPM2_RC_ALL_1 0xffffffff

/* Check our ability to determine RC format. The spec is massively (IMHO)
 * confusing on this point. See section 6.6.3 from part 2 for some clarity.
 * specifically the NOTE immediately before table 17
 */
static void
tpm2_rc_is_format_zero_true (void **state)
{
    (void) state;

    TSS2_RC rc = 0xffffff7f;

    assert_true (tpm2_rc_is_format_zero (rc));
}
static void
tpm2_rc_is_format_zero_false (void **state)
{
    (void) state;

    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_false (tpm2_rc_is_format_zero (rc));
}
static void
tpm2_rc_is_format_one_true (void **state)
{
    (void) state;

    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_true (tpm2_rc_is_format_one (rc));
}
static void
tpm2_rc_is_format_one_false (void **state)
{
    (void) state;

    TSS2_RC rc = 0xffffff7f;

    assert_false (tpm2_rc_is_format_one (rc));
}
/* Bits 7 and 8 in the TSS2_RC are set to 0 for TPM1.2 return codes.
 * Here we test to be sure the is_tpm2_rc function identifies this RC as such.
 * All other bits in the RC are set to 1 since the comparison is done using a
 * logical AND operation.
 */
static void
tpm2_rc_is_tpm12_true (void **state)
{
    (void) state;

    /* bits 7 & 8 clear */
    TSS2_RC rc = 0xfffffe7f;

    assert_true (tpm2_rc_is_tpm12 (rc));
}
static void
tpm2_rc_is_tpm12_false (void **state)
{
    (void) state;

    TSS2_RC rc = 0xfffffe7f;

    assert_false (tpm2_rc_is_tpm2 (rc));
}
/* If either of bits 7 or 8 are set the response code is a TPM2 response.
 * The next 3 tests go through the 3 possible permutations (01, 10 & 11)
 * for these two bits.
 */
static void
tpm2_rc_is_tpm2_01 (void **state)
{
    (void) state;

    /* bit 7 set, bit 8 clear */
    TSS2_RC rc = 0xfffffeff;

    assert_true (tpm2_rc_is_tpm2 (rc));
}
static void
tpm2_rc_is_tpm2_10 (void **state)
{
    (void) state;

    /* bit 7 clear, bit 8 set */
    TSS2_RC rc = 0xffffff7f;

    assert_true (tpm2_rc_is_tpm2 (rc));
}
static void
tpm2_rc_is_tpm2_11 (void **state)
{
    (void) state;

    /* bit 7 and 8 set */
    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_true (tpm2_rc_is_tpm2 (rc));
}
/* Vendor defined response codes have bit 8 and 10 set and bit 7 cleared.
 */
static void
tpm2_rc_is_vendor_defined_code_all_but_7 (void **state)
{
    (void) state;

    /* bit 7 clear, bit 8 and 10 set */
    TSS2_RC rc = 0xffffff7f;

    assert_true (tpm2_rc_is_vendor_defined (rc));
}
/* Negative case for bit 7 */
static void
tpm2_rc_is_vendor_defined_code_7_set (void **state)
{
    (void) state;

    /* bit 7, 8 and 10 set */
    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_false (tpm2_rc_is_vendor_defined (rc));
}
/* Negative case for bit 8 */
static void
tpm2_rc_is_vendor_defined_code_8_unset (void **state)
{
    (void) state;

    /* bit 7 and 8 clear, bit 10 set */
    TSS2_RC rc = 0xfffffe7f;

    assert_false (tpm2_rc_is_vendor_defined (rc));
}
/* Negative case for bit 10 */
static void
tpm2_rc_is_vendor_defined_code_10_unset (void **state)
{
    (void) state;

    /* bit 7 and 10 clear, bit 8 set */
    TSS2_RC rc = 0xfffffb7f;

    assert_false (tpm2_rc_is_vendor_defined (rc));
}
/* Case to show that an unrelated bit has no effect. */
static void
tpm2_rc_is_vendor_defined_code_no_9 (void **state)
{
    (void) state;

    /* bit 7 and 9 clear, bit 8 and 10 set */
    TSS2_RC rc = 0xfffffd7f;

    assert_true (tpm2_rc_is_vendor_defined (rc));
}
/* Warning codes have bit 8 and 11 set, and bits 7 and 10 clear.
 */
static void
tpm2_rc_is_warning_code_success (void **state)
{
    (void) state;

    /* bit 7 and 10 clear, bit 8 and 11 set */
    TSS2_RC rc = 0xfffff97f;

    assert_true (tpm2_rc_is_warning_code (rc));
}
/* Negitive case for bit 8 */
static void
tpm2_rc_is_warning_code_8_unset (void **state)
{
    (void) state;

    /* bit 7, 8 and 10 clear, bit 11 set */
    TSS2_RC rc = 0xfffffa7f;

    assert_false (tpm2_rc_is_warning_code (rc));
}
/* Negative case for bit 7 */
static void
tpm2_rc_is_warning_code_7_set (void **state)
{
    (void) state;

    /* bit 7, 8 and 11 set, bit 10 clear */
    TSS2_RC rc = 0xfffff9ff;

    assert_false (tpm2_rc_is_warning_code (rc));
}
/* Negative case for bit 10 */
static void
tpm2_rc_is_warning_code_10_set (void **state)
{
    (void) state;

    /* bit 8, 10 and 11 set, bit 7 clear */
    TSS2_RC rc = 0xfffff7f;

    assert_false (tpm2_rc_is_warning_code (rc));
}
/* Negative case for bit 11
 */
static void
tpm2_rc_is_warning_code_11_unset (void **state)
{
    (void) state;

    /* bit 8 set, bits 7, 10 and 11 clear */
    TSS2_RC rc = 0xfffff37f;

    assert_false (tpm2_rc_is_warning_code (rc));
}
/* Error code in bit [6:0] if bit 8 set, and bit 7, 10 and 11 clear.
 */
static void
tpm2_rc_is_error_code_success (void **state)
{
    (void) state;

    TSS2_RC rc = 0xfffff37f;

    assert_true (tpm2_rc_is_error_code (rc));
}
/* Negative case for bit 8 */
static void
tpm2_rc_is_error_code_8_unset (void **state)
{
    (void) state;

    /* bit 7, 8, 10 and 11 clear */
    TSS2_RC rc = 0xfffff27f;

    assert_false (tpm2_rc_is_error_code (rc));
}
/* Negative case for bit 7 */
static void
tpm2_rc_is_error_code_7_set (void **state)
{
    (void) state;

    /* bit 7 and 8 set, bit 10 and 11 clear*/
    TSS2_RC rc = 0xfffff3ff;

    assert_false (tpm2_rc_is_error_code (rc));
}
/* Negative case for bit 10 */
static void
tpm2_rc_is_error_code_10_set (void **state)
{
    (void) state;

    /* bit 8 and 10 set, bit 7 and 11 clear */
    TSS2_RC rc = 0xfffff77f;

    assert_false (tpm2_rc_is_error_code (rc));
}
/* Negative case for bit 11 */
static void
tpm2_rc_is_error_code_11_set (void **state)
{
    (void) state;

    /* bit 8 and 11 set, bit 7 and 10 clear*/
    TSS2_RC rc = 0xfffffb7f;

    assert_false (tpm2_rc_is_error_code (rc));
}
/* Error code in bits [5:0] with parameter number in bits [11:8] when
 * bits 6 and 7 are set.
 */
static void
tpm2_rc_is_error_code_with_parameter_success (void **state)
{
    (void) state;

    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_true (tpm2_rc_is_error_code_with_parameter (rc));
}
/* Negative case for bit 6 */
static void
tpm2_rc_is_error_code_with_parameter_6_unset (void **state)
{
    (void) state;

    /* bit 6 clear, bit 7 set */
    TSS2_RC rc = 0xffffffbf;

    assert_false (tpm2_rc_is_error_code_with_parameter (rc));
}
/* Negative case for bit 7 */
static void
tpm2_rc_is_error_code_with_parameter_7_unset (void **state)
{
    (void) state;

    /* bit 6 set, bit 7 clear */
    TSS2_RC rc = 0xffffff7f;

    assert_false (tpm2_rc_is_error_code_with_parameter (rc));
}
/* Error code in bits [5:0] with handle number in bits [10:8] when
 * bit 7 is set and bits 6 and 11 are clear.
 */
static void
tpm2_rc_is_error_code_with_handle_success (void **state)
{
    (void) state;

    TSS2_RC rc = 0xfffff7bf;

    assert_true (tpm2_rc_is_error_code_with_handle (rc));
}
/* Negative case for bit 6 */
static void
tpm2_rc_is_error_code_with_handle_6_set (void **state)
{
    (void) state;

    /* bit 6 and 7 set, bit 11 clear*/
    TSS2_RC rc = 0xfffff7ff;

    assert_false (tpm2_rc_is_error_code_with_handle (rc));
}
/* Negative case for bit 7 */
static void
tpm2_rc_is_error_code_with_handle_7_unset (void **state)
{
    (void) state;

    /* bit 6, 7 and 11 clear */
    TSS2_RC rc = 0xfffff73f;

    assert_false (tpm2_rc_is_error_code_with_handle (rc));
}
/* Negative case for bit 11 */
static void
tpm2_rc_is_error_code_with_handle_11_set (void **state)
{
    (void) state;

    /* bit 6 clear, bit 7 and 11 clear */
    TSS2_RC rc = 0xffffffbf;

    assert_false (tpm2_rc_is_error_code_with_handle (rc));
}
/* Error code in bits [05:00] with session number in bits [10:08] when
 * bit 6 is clear and bits 7 and 11 set.
 */
static void
tpm2_rc_is_error_code_with_session_success (void **state)
{
    (void) state;

    /* bit 6 clear, bits 7 & 11 set */
    TSS2_RC rc = 0xffffffbf;

    assert_true (tpm2_rc_is_error_code_with_session (rc));
}
/* Negative case for bit 6 */
static void
tpm2_rc_is_error_code_with_session_6_set (void **state)
{
    (void) state;

    /* bits 6, 7 & 11 set */
    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_false (tpm2_rc_is_error_code_with_session (rc));
}
/* Negative case for bit 7 */
static void
tpm2_rc_is_error_code_with_session_7_unset (void **state)
{
    (void) state;

    /* bits 6 & 7 clear, bit 11 set */
    TSS2_RC rc = 0xffffff3f;

    assert_false (tpm2_rc_is_error_code_with_session (rc));
}
/* Negative case for bit 11 */
static void
tpm2_rc_is_error_code_with_session_11_unset (void **state)
{
    (void) state;

    /* bits 6 & 11 clear, bit 7 set */
    TSS2_RC rc = 0xfffff7bf;

    assert_false (tpm2_rc_is_error_code_with_session (rc));
}
/* Isolate bits [06:00] of the TSS2_RC.
 * The first of these tests ensures that when all bits are set that we only
 * get back an int with the bits [06:00] set.
 */
static void
tpm2_rc_get_code_7bit_all (void **state)
{
    (void) state;

    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_int_equal (tpm2_rc_get_code_6bit (rc), 0x0000003f);
}
static void
tpm2_rc_get_code_7bit_general_failure (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_6BIT_ERROR_MASK | TSS2_BASE_RC_GENERAL_FAILURE;

    assert_int_equal (tpm2_rc_get_code_6bit (rc), TSS2_BASE_RC_GENERAL_FAILURE);
}
/* Isolate bits [05:00] of the TSS2_RC.
 * This test ensures that the tpm2_rc_get_code_6bit returns only bits [05:00]
 * unmodified.
 */
static void
tpm2_rc_get_code_6bit_all (void **state)
{
    (void) state;

    TSS2_RC rc = TPM2_RC_ALL_1;

    assert_int_equal (tpm2_rc_get_code_6bit (rc), 0x0000003f);
}
static void
tpm2_rc_get_code_6bit_general_failure (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_6BIT_ERROR_MASK | TSS2_BASE_RC_GENERAL_FAILURE;

    assert_int_equal (tpm2_rc_get_code_6bit (rc), TSS2_BASE_RC_GENERAL_FAILURE);
}
/* Isolate bits [11:08] from the TSS2_RC.
 */
static void
tpm2_rc_get_parameter_number_f (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_PARAMETER_MASK | TPM2_RC_F;

    assert_int_equal (tpm2_rc_get_parameter_number (rc), TPM2_RC_F);
}
static void
tpm2_rc_get_parameter_number_9 (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_PARAMETER_MASK | TPM2_RC_9;

    assert_int_equal (tpm2_rc_get_parameter_number (rc), TPM2_RC_9);
}
/* Isolate bits [10:08] from the TSS2_RC.
 */
static void
tpm2_rc_get_handle_number_1 (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_HANDLE_MASK | TPM2_RC_1;

    assert_int_equal (tpm2_rc_get_handle_number (rc), TPM2_RC_1);
}
/* The largest handle number possible */
static void
tpm2_rc_get_handle_number_7 (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_HANDLE_MASK | TPM2_RC_7;

    assert_int_equal (tpm2_rc_get_handle_number (rc), TPM2_RC_7);
}
/* A negative case to test for handle numbers beyond what's possible */
static void
tpm2_rc_get_handle_number_f (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_HANDLE_MASK | TPM2_RC_F;

    assert_int_not_equal (tpm2_rc_get_handle_number (rc), TPM2_RC_F);
}
/* Isolate bits [10:08] from the TSS2_RC. This is redundant but it tests
 * the functions that expose functionality which are themselves redundant.
 */
static void
tpm2_rc_get_session_number_1 (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_SESSION_MASK | TPM2_RC_1;

    assert_int_equal (tpm2_rc_get_session_number (rc), TPM2_RC_1);
}
static void
tpm2_rc_get_session_number_7 (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_SESSION_MASK | TPM2_RC_7;

    assert_int_equal (tpm2_rc_get_session_number (rc), TPM2_RC_7);
}
static void
tpm2_rc_get_session_number_f (void **state)
{
    (void) state;

    TSS2_RC rc = ~TPM2_RC_SESSION_MASK | TPM2_RC_F;

    assert_int_not_equal (tpm2_rc_get_session_number (rc), TPM2_RC_F);
}
/* Isolate the various error layers. To test this we set every bit in the RC
 * and then selectively disable bits using a logical AND to make the error
 * level meaningful. We then compare the result of the tpm2_rc_get_level
 * function to the level that we set to be sure that all other bits were
 * cleared.
 */
static void
tpm2_rc_get_layer_tpm (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_TPM_RC_LAYER;

    assert_int_equal (tpm2_rc_get_layer (rc), TSS2_TPM_RC_LAYER);
}
static void
tpm2_rc_get_layer_sys (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_SYS_RC_LAYER;

    assert_int_equal (tpm2_rc_get_layer (rc), TSS2_SYS_RC_LAYER);
}
static void
tpm2_rc_get_layer_tcti (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_TCTI_RC_LAYER;

    assert_int_equal (tpm2_rc_get_layer (rc), TSS2_TCTI_RC_LAYER);
}
/* Check our ability to determine the source of the 
 */
static void
tpm2_rc_is_from_tss_sys (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_SYS_RC_LAYER;

    assert_true (tpm2_rc_is_from_tss (rc));
}
static void
tpm2_rc_is_from_tss_tpm (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_TPM_RC_LAYER;

    assert_false (tpm2_rc_is_from_tss (rc));
}
static void
tpm2_rc_is_from_tss_tcti (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_TCTI_RC_LAYER;

    assert_true (tpm2_rc_is_from_tss (rc));
}
/* Isolate the base error code from a TSS error.
 */
static void
tpm2_rc_get_tss_err_code_general_from_tcti (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;

    assert_int_equal (TSS2_BASE_RC_GENERAL_FAILURE,
                      tpm2_rc_get_tss_err_code (rc));
}
static void
tpm2_rc_get_tss_err_code_try_again_from_tcti (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_TCTI_RC_TRY_AGAIN;

    assert_int_equal (TSS2_BASE_RC_TRY_AGAIN,
                      tpm2_rc_get_tss_err_code (rc));
}
static void
tpm2_rc_get_tss_err_code_abi_mismatch_from_sys (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_SYS_RC_ABI_MISMATCH;

    assert_int_equal (TSS2_BASE_RC_ABI_MISMATCH,
                      tpm2_rc_get_tss_err_code (rc));
}
static void
tpm2_rc_get_tss_err_code_bad_size_from_sys (void **state)
{
    (void) state;

    TSS2_RC rc = TSS2_SYS_RC_BAD_SIZE;

    assert_int_equal (TSS2_BASE_RC_BAD_SIZE,
                      tpm2_rc_get_tss_err_code (rc));
}
/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;
int
main (int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test (tpm2_rc_is_format_zero_true),
        cmocka_unit_test (tpm2_rc_is_format_zero_false),
        cmocka_unit_test (tpm2_rc_is_format_one_true),
        cmocka_unit_test (tpm2_rc_is_format_one_false),
        cmocka_unit_test (tpm2_rc_is_tpm12_true),
        cmocka_unit_test (tpm2_rc_is_tpm12_false),
        cmocka_unit_test (tpm2_rc_is_tpm2_01),
        cmocka_unit_test (tpm2_rc_is_tpm2_10),
        cmocka_unit_test (tpm2_rc_is_tpm2_11),
        cmocka_unit_test (tpm2_rc_is_vendor_defined_code_all_but_7),
        cmocka_unit_test (tpm2_rc_is_vendor_defined_code_7_set),
        cmocka_unit_test (tpm2_rc_is_vendor_defined_code_8_unset),
        cmocka_unit_test (tpm2_rc_is_vendor_defined_code_10_unset),
        cmocka_unit_test (tpm2_rc_is_vendor_defined_code_no_9),
        cmocka_unit_test (tpm2_rc_is_warning_code_success),
        cmocka_unit_test (tpm2_rc_is_warning_code_8_unset),
        cmocka_unit_test (tpm2_rc_is_warning_code_7_set),
        cmocka_unit_test (tpm2_rc_is_warning_code_10_set),
        cmocka_unit_test (tpm2_rc_is_warning_code_11_unset),
        cmocka_unit_test (tpm2_rc_is_error_code_success),
        cmocka_unit_test (tpm2_rc_is_error_code_8_unset),
        cmocka_unit_test (tpm2_rc_is_error_code_7_set),
        cmocka_unit_test (tpm2_rc_is_error_code_10_set),
        cmocka_unit_test (tpm2_rc_is_error_code_11_set),
        cmocka_unit_test (tpm2_rc_is_error_code_with_parameter_success),
        cmocka_unit_test (tpm2_rc_is_error_code_with_parameter_6_unset),
        cmocka_unit_test (tpm2_rc_is_error_code_with_parameter_7_unset),
        cmocka_unit_test (tpm2_rc_is_error_code_with_handle_success),
        cmocka_unit_test (tpm2_rc_is_error_code_with_handle_6_set),
        cmocka_unit_test (tpm2_rc_is_error_code_with_handle_7_unset),
        cmocka_unit_test (tpm2_rc_is_error_code_with_handle_11_set),
        cmocka_unit_test (tpm2_rc_is_error_code_with_session_success),
        cmocka_unit_test (tpm2_rc_is_error_code_with_session_6_set),
        cmocka_unit_test (tpm2_rc_is_error_code_with_session_7_unset),
        cmocka_unit_test (tpm2_rc_is_error_code_with_session_11_unset),
        cmocka_unit_test (tpm2_rc_get_code_7bit_all),
        cmocka_unit_test (tpm2_rc_get_code_7bit_general_failure),
        cmocka_unit_test (tpm2_rc_get_code_6bit_all),
        cmocka_unit_test (tpm2_rc_get_code_6bit_general_failure),
        cmocka_unit_test (tpm2_rc_get_parameter_number_f),
        cmocka_unit_test (tpm2_rc_get_parameter_number_9),
        cmocka_unit_test (tpm2_rc_get_handle_number_1),
        cmocka_unit_test (tpm2_rc_get_handle_number_7),
        cmocka_unit_test (tpm2_rc_get_handle_number_f),
        cmocka_unit_test (tpm2_rc_get_session_number_1),
        cmocka_unit_test (tpm2_rc_get_session_number_7),
        cmocka_unit_test (tpm2_rc_get_session_number_f),
        cmocka_unit_test (tpm2_rc_get_layer_tpm),
        cmocka_unit_test (tpm2_rc_get_layer_sys),
        cmocka_unit_test (tpm2_rc_get_layer_tcti),
        cmocka_unit_test (tpm2_rc_is_from_tss_tpm),
        cmocka_unit_test (tpm2_rc_is_from_tss_sys),
        cmocka_unit_test (tpm2_rc_is_from_tss_tcti),
        cmocka_unit_test (tpm2_rc_get_tss_err_code_general_from_tcti),
        cmocka_unit_test (tpm2_rc_get_tss_err_code_try_again_from_tcti),
        cmocka_unit_test (tpm2_rc_get_tss_err_code_abi_mismatch_from_sys),
        cmocka_unit_test (tpm2_rc_get_tss_err_code_bad_size_from_sys),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
