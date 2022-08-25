/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <setjmp.h>
#include <cmocka.h>
#include <tss2/tss2_mu.h>
#include "object.h"
#include "log.h"

#define NEGATIVE_PARENT -1

tool_rc tpm2_util_object_fetch_tssprivkey_from_file(const char *objectstr,
    BIO **input_bio, TSSPRIVKEY_OBJ **tpk) {

    UNUSED(objectstr);
    UNUSED(input_bio);
    /*
     * Create a blob and copy over to tpk such that tpk->parent is negative
     */
    TSSPRIVKEY_OBJ *tpk_internal = TSSPRIVKEY_OBJ_new();
    tpk_internal->type = OBJ_txt2obj(OID_loadableKey, 1);
    tpk_internal->emptyAuth = true;

    int returnval = ASN1_INTEGER_set(tpk_internal->parent, NEGATIVE_PARENT);
    if (returnval != 1) {
        /**
         * Unable to set parent required for testing
         */
        LOG_ERR("Unable to set ASN1Integer parent");
        return tool_rc_general_error;
    }

    (*tpk) = tpk_internal;
    return tool_rc_success;
}

static void test_tpm2_util_object_fetch_parent_from_tpk(void **state) {

    UNUSED(state);
    uint64_t val;

    tool_rc rc = tpm2_util_object_fetch_parent_from_tpk("", &val);

    assert_int_equal(rc, tool_rc_success);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tpm2_util_object_fetch_parent_from_tpk)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
