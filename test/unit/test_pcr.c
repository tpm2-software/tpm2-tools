/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
// All rights reserved.
//
//**********************************************************************;
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "pcr.h"
#include "tpm2_util.h"

static void test_pcr_alg_nice_names(void **state) {

    (void) state;

    TPML_PCR_SELECTION friendly_pcr_selections =
            TPML_PCR_SELECTION_EMPTY_INIT;

    bool result = pcr_parse_selections("sha256:16,17,18+0x0b:16,17,18",
            &friendly_pcr_selections);
    assert_true(result);

    TPML_PCR_SELECTION raw_pcr_selections =
            TPML_PCR_SELECTION_EMPTY_INIT;

    result = pcr_parse_selections("0xb:16,17,18+0x0b:16,17,18",
            &raw_pcr_selections);
    assert_true(result);

    assert_memory_equal(&friendly_pcr_selections, &raw_pcr_selections,
            sizeof(raw_pcr_selections));
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pcr_alg_nice_names)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
