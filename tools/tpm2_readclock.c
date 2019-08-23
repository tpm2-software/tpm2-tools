/* SPDX-License-Identifier: BSD-3-Clause */
#include <inttypes.h>

#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

static void print_time(TPMS_TIME_INFO *current_time) {

    tpm2_tool_output("time: %"PRIu64"\n", current_time->time);

    tpm2_tool_output("clock_info:\n");

    tpm2_tool_output("  clock: %"PRIu64"\n",
            current_time->clockInfo.clock);

    tpm2_tool_output("  reset_count: %"PRIu32"\n",
            current_time->clockInfo.resetCount);

    tpm2_tool_output("  restart_count: %"PRIu32"\n",
            current_time->clockInfo.restartCount);

    tpm2_tool_output("  safe: %s\n",
            current_time->clockInfo.safe ? "yes" : "no");
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMS_TIME_INFO *current_time = NULL;
    tool_rc rc = tpm2_readclock(ectx, &current_time);
    if (rc == tool_rc_success) {
        print_time(current_time);
        Esys_Free(current_time);
    }

    return rc;
}
