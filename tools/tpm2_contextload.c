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

static bool on_option(char key, char *value) {

    switch (key) {
    case 'S':
        ctx.session_path = value;
        break;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "session",  required_argument,  NULL, 'S' },
    };

    *opts = tpm2_options_new("S:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool option_fail = false;
    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        option_fail = true;
    }

    if (option_fail) {
        return tool_rc_general_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
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
