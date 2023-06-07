/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <setjmp.h>
#include <cmocka.h>

#include "pcr.h"
#include "tpm2_util.h"

static void test_pcr_alg_nice_names(void **state) {

    (void) state;

    TPML_PCR_SELECTION friendly_pcr_selections =
    TPML_PCR_SELECTION_EMPTY_INIT;

    bool result = pcr_parse_selections("sha256:16,17,18+0x0b:16,17,18",
            &friendly_pcr_selections, NULL);
    assert_true(result);

    TPML_PCR_SELECTION raw_pcr_selections =
    TPML_PCR_SELECTION_EMPTY_INIT;

    result = pcr_parse_selections("0xb:16,17,18+0x0b:16,17,18",
            &raw_pcr_selections, NULL);
    assert_true(result);

    assert_memory_equal(&friendly_pcr_selections, &raw_pcr_selections,
            sizeof(raw_pcr_selections));

    // select from PCR bank sm3_256
    TPML_PCR_SELECTION friendly_pcr_selections_sm3 =
    TPML_PCR_SELECTION_EMPTY_INIT;

    bool result_sm3 = pcr_parse_selections("sm3_256:16,17,18+0x12:16,17,18",
            &friendly_pcr_selections_sm3, NULL);
    assert_true(result_sm3);

    TPML_PCR_SELECTION raw_pcr_selections_sm3 =
    TPML_PCR_SELECTION_EMPTY_INIT;

    result_sm3 = pcr_parse_selections("0x12:16,17,18+0x12:16,17,18",
            &raw_pcr_selections_sm3, NULL);
    assert_true(result_sm3);

    assert_memory_equal(&friendly_pcr_selections_sm3, &raw_pcr_selections_sm3,
            sizeof(raw_pcr_selections_sm3));

    // select from PCR bank sha3_256
    TPML_PCR_SELECTION friendly_pcr_selections_sha3_256 =
    TPML_PCR_SELECTION_EMPTY_INIT;

    bool result_sha3 = pcr_parse_selections("sha3_256:16,17,18+0x27:16,17,18",
            &friendly_pcr_selections_sha3_256, NULL);
    assert_true(result_sha3);

    TPML_PCR_SELECTION raw_pcr_selections_sha3_256 =
    TPML_PCR_SELECTION_EMPTY_INIT;

    result_sha3 = pcr_parse_selections("0x27:16,17,18+0x27:16,17,18",
            &raw_pcr_selections_sha3_256, NULL);
    assert_true(result_sha3);

    assert_memory_equal(&friendly_pcr_selections_sha3_256, &raw_pcr_selections_sha3_256,
            sizeof(raw_pcr_selections_sha3_256));
}

static void test_pcr_forward_seal(void **state) {

    (void) state;

    tpm2_forwards forwards = {};
    TPML_PCR_SELECTION raw_pcr_selections_forward =
    TPML_PCR_SELECTION_EMPTY_INIT;
    // test forward sealing
    bool result_forward = pcr_parse_selections("sha1:4,5=da39a3ee5e6b4b0d3255bfef95601890afd80709,6",
            &raw_pcr_selections_forward, &forwards);
    assert_true(result_forward);
    result_forward = pcr_parse_selections("sha1:4,5=da39a3ee5e6b4b0d3255bfef95601890afd80709,6+sha256:0,1=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,2",
            &raw_pcr_selections_forward, &forwards);
    assert_true(result_forward);

    // Out-of-range
    result_forward = pcr_parse_selections(
            "sha256:32",
            &raw_pcr_selections_forward, &forwards);
    assert_false(result_forward);

    // Trailing digest
    result_forward = pcr_parse_selections(
            "sha1:4,5=da39a3ee5e6b4b0d3255bfef95601890afd80709",
            &raw_pcr_selections_forward, &forwards);
    assert_true(result_forward);

    // 0x digest
    result_forward = pcr_parse_selections(
            "sha1:4,5=0xda39a3ee5e6b4b0d3255bfef95601890afd80709",
            &raw_pcr_selections_forward, &forwards);
    assert_true(result_forward);

    // Digest odd length:
    result_forward = pcr_parse_selections(
            "sha1:4,5=da39a",
            &raw_pcr_selections_forward, &forwards);
    assert_false(result_forward);

    // Digest too short:
    result_forward = pcr_parse_selections(
            "sha1:4,5=da39",
            &raw_pcr_selections_forward, &forwards);
    assert_false(result_forward);

    // Digest too long:
    result_forward = pcr_parse_selections(
            "sha1:4,5=11111111111111111111111111111111111111111111111111",
            &raw_pcr_selections_forward, &forwards);
    assert_false(result_forward);

    // Digest specified but no forwards
    result_forward = pcr_parse_selections(
            "sha1:4,5=da39a3ee5e6b4b0d3255bfef95601890afd80709",
            &raw_pcr_selections_forward, NULL);
    assert_false(result_forward);

    // Invalid PCR#
    result_forward = pcr_parse_selections(
            "sha1:boo,5",
            &raw_pcr_selections_forward, NULL);
    assert_false(result_forward);

    TPML_PCR_SELECTION pcr_selections_sha256 =
        TPML_PCR_SELECTION_EMPTY_INIT;

    result_forward = pcr_parse_selections("sha256:16,17,18",
            &pcr_selections_sha256, NULL);
    assert_true(result_forward);

    TPML_PCR_SELECTION forward_pcr_selections_sha256 =
        TPML_PCR_SELECTION_EMPTY_INIT;

    result_forward = pcr_parse_selections("sha256:16=1616161616161616161616161616161616161616161616161616161616161616,17,18",
            &forward_pcr_selections_sha256, &forwards);
    assert_true(result_forward);

    assert_memory_equal(&pcr_selections_sha256, &forward_pcr_selections_sha256,
            sizeof(pcr_selections_sha256));
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pcr_alg_nice_names),
        cmocka_unit_test(test_pcr_forward_seal)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
