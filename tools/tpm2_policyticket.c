/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policyticket_ctx tpm2_policyticket_ctx;
struct tpm2_policyticket_ctx {
    const char *session_path;
    tpm2_session *session;

    const char *policy_digest_path;

    char *policy_timeout_path;

    const char *policy_qualifier_data;

    char *policy_ticket_path;

    const char *auth_name_file;
};

static tpm2_policyticket_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'L':
        ctx.policy_digest_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'n':
        ctx.auth_name_file = value;
        break;
    case 'q':
        ctx.policy_qualifier_data = value;
        break;
    case 0:
        ctx.policy_ticket_path = value;
        break;
    case 1:
        ctx.policy_timeout_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",         required_argument, NULL, 'L' },
        { "session",        required_argument, NULL, 'S' },
        { "name",           required_argument, NULL, 'n' },
        { "qualification",  required_argument, NULL, 'q' },
        { "ticket",         required_argument, NULL,  0  },
        { "timeout",        required_argument, NULL,  1  },
    };

    *opts = tpm2_options_new("L:S:n:q:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.auth_name_file) {
        LOG_ERR("Must specify -n authname file.");
        return false;
    }

    if (!ctx.policy_ticket_path) {
        LOG_ERR("Must specify --ticket policy ticket file.");
        return false;
    }

    if (!ctx.policy_timeout_path) {
        LOG_ERR("Must specify --timeout policy timeout file.");
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

    rc = tpm2_policy_build_policyticket(ectx, ctx.session,
        ctx.policy_timeout_path, ctx.policy_qualifier_data,
        ctx.policy_ticket_path, ctx.auth_name_file);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policyticket TPM");
        return rc;
    }

    rc = tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_path);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policyticket", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
