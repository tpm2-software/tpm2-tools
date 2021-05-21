/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2.h"

typedef struct tpm2_contextload_ctx tpm2_contextload_ctx;
struct tpm2_contextload_ctx {
    const char *session_path;
    tpm2_session *session;
};

static tpm2_contextload_ctx ctx;

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Argument takes one file name for session data");
        return false;
    }

    ctx.session_path = argv[0];

    return true;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify session file as an argument.");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_args, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not restore session from the specified file");
        return rc;
    }

    ESYS_TR sessionhandle = tpm2_session_get_handle(ctx.session);
    if (!sessionhandle) {
        LOG_ERR("Session handle cannot be null");
        return tool_rc_general_error;
    }

    TPM2_HANDLE tpm_handle;
    TSS2_RC rv = Esys_TR_GetTpmHandle(ectx, sessionhandle, &tpm_handle);
    if (rv != TSS2_RC_SUCCESS) {
        return tool_rc_general_error;
    }

    tpm2_tool_output("Session-Handle: 0x%.8"PRIx32"\n", tpm_handle);

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("contextload", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
