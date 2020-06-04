/* SPDX-License-Identifier: BSD-3-Clause */
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMS_TIME_INFO *current_time = NULL;
    tool_rc rc = tpm2_readclock(ectx, &current_time);
    if (rc == tool_rc_success) {
        tpm2_util_print_time(current_time);
        Esys_Free(current_time);
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("readclock", NULL, tpm2_tool_onrun, NULL, NULL)
