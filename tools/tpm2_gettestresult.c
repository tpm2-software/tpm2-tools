/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
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
    TSS2_RC rval = Esys_GetTestResult(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &output, &status);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SelfTest, rval);
        return tool_rc_from_tpm(rval);
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

    if(output->size > 0){
        tpm2_tool_output("\ndata: ");
        print_yaml_indent(1);
        tpm2_util_hexdump(output->buffer, output->size);
    }
    tpm2_tool_output("\n");

    rc = tool_rc_success;
out:
    free(output);

    return rc;
}
