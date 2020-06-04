/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policyauthvalue_ctx tpm2_policyauthvalue_ctx;
struct tpm2_policyauthvalue_ctx {
    //File path for the session context data
    const char *session_path;
    //File path for storing the policy digest output
    const char *policy_digest_path;

    tpm2_session *session;
};

static tpm2_policyauthvalue_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'L':
        ctx.policy_digest_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",  required_argument, NULL, 'L' },
        { "session", required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("S:L:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }
    return true;
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
        return rc;
    }

    rc = tpm2_policy_build_policyauthvalue(ectx, ctx.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policyauthvalue TPM");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policyauthvalue", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
