/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policyauthorize_ctx tpm2_policyauthorize_ctx;
struct tpm2_policyauthorize_ctx {
    //File path for the session context data
    const char *session_path;
    //File path for the policy digest that will be authorized
    const char *policy_digest_path;
    //File path for the policy qualifier data
    const char *qualifier_data_path;
    //File path for the verifying public key name
    const char *verifying_pubkey_name_path;
    //File path for the verification ticket
    const char *ticket_path;
    //File path for storing the policy digest output
    const char *out_policy_dgst_path;

    tpm2_session *session;
    TPM2B_DIGEST *policy_digest;
};

static tpm2_policyauthorize_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'i':
        ctx.policy_digest_path = value;
        break;
    case 'q':
        ctx.qualifier_data_path = value;
        break;
    case 'n':
        ctx.verifying_pubkey_name_path = value;
        break;
    case 't':
        ctx.ticket_path = value;
        break;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",        required_argument, NULL, 'L' },
        { "session",       required_argument, NULL, 'S' },
        { "input",         required_argument, NULL, 'i' },
        { "qualification", required_argument, NULL, 'q' },
        { "name",          required_argument, NULL, 'n' },
        { "ticket",        required_argument, NULL, 't' },
    };

    *opts = tpm2_options_new("L:S:i:q:n:t:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

bool is_check_input_options_ok(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify a session file with -S.");
        return false;
    }

    if (!ctx.verifying_pubkey_name_path) {
        LOG_ERR("Must specify name of the public key used for verification -n.");
        return false;
    }

    return true;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!is_check_input_options_ok()) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_policyauthorize(ectx, ctx.session,
            ctx.policy_digest_path, ctx.qualifier_data_path,
            ctx.verifying_pubkey_name_path, ctx.ticket_path);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build tpm authorized policy");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.out_policy_dgst_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    free(ctx.policy_digest);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policyauthorize", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
