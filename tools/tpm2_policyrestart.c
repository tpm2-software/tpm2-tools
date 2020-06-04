/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

typedef struct tpm2_policyreset_ctx tpm2_policyreset_ctx;
struct tpm2_policyreset_ctx {
    char *path;
    tpm2_session *session;
};

static tpm2_policyreset_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'S':
        ctx.path = value;
        break;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "session", required_argument,  NULL, 'S' },
    };

    *opts = tpm2_options_new("S:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_session_restore(ectx, ctx.path, false, &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tpm2_session_restart(ectx, ctx.session);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policyrestart", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
