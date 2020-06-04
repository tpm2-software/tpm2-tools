/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    tool_rc rc = tool_rc_general_error;

    TPM2_RC status;
    TPM2B_MAX_BUFFER *output = NULL;

    /*
     * If TPM2_SelfTest() has not been executed and a testable function has not been tested, testResult will be
     * TPM_RC_NEEDS_TEST. If TPM2_SelfTest() has been received and the tests are not complete,
     * testResult will be TPM_RC_TESTING. If testing of all functions is complete without functional failures,
     * testResult will be TPM_RC_SUCCESS. If any test failed, testResult will be TPM_RC_FAILURE.
     */
    tool_rc tmp_rc = tpm2_gettestresult(ectx, &output, &status);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }

    tpm2_tool_output("status: ");
    print_yaml_indent(1);

    status &= TPM2_RC_TESTING;

    switch (status) {
    case TPM2_RC_SUCCESS:
        tpm2_tool_output("success");
        break;
    case TPM2_RC_TESTING:
        tpm2_tool_output("testing");
        break;
    case TPM2_RC_NEEDS_TEST:
        tpm2_tool_output("needs-test");
        break;
    default:
        LOG_ERR("Unknown testing result, got: 0x%x", status);
        goto out;
    }

    if (output->size > 0) {
        tpm2_tool_output("\ndata: ");
        print_yaml_indent(1);
        tpm2_util_hexdump(output->buffer, output->size);
    }
    tpm2_tool_output("\n");

    rc = tool_rc_success;
    out: free(output);

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("gettestresult", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
