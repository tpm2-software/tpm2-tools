/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct changepps_ctx changepps_ctx;
struct changepps_ctx {
    const char *auth_str;
    tpm2_session *auth_session;
};

static changepps_ctx ctx;


static bool on_option(char key, char *value) {

    switch (key) {
    case 'p':
        ctx.auth_str = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "auth", required_argument, NULL, 'p' },
    };

    *opts = tpm2_options_new("p:", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth_str,
        &ctx.auth_session,
        false);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed loading platform auth.");
        return rc;
    }

    return tpm2_changepps(ectx, ctx.auth_session);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth_session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("changepps", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
