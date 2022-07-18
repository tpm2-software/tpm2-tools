/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policyor_ctx tpm2_policyor_ctx;
struct tpm2_policyor_ctx {
    //File path for the session context data
    const char *session_path;
    //List of policy digests that will be compounded
    TPML_DIGEST policy_list;
    //File path for storing the policy digest output
    const char *out_policy_dgst_path;

    TPM2B_DIGEST *policy_digest;
    tpm2_session *session;
};

static tpm2_policyor_ctx ctx;

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'l':
        result = tpm2_policy_parse_policy_list(value, &ctx.policy_list);
        if (!result) {
            return false;
        }
        break;
    }

    return result;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("specify single argument for policy list.");
        return false;
    }

    bool result = tpm2_policy_parse_policy_list(argv[0], &ctx.policy_list);
    if (!result) {
        return false;
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",                 required_argument, NULL, 'L' },
        { "session",                required_argument, NULL, 'S' },
        //Option retained for backwards compatibility - See issue#1894
        { "policy-list",            required_argument, NULL, 'l' },
    };

    *opts = tpm2_options_new("L:S:l:", ARRAY_LEN(topts), topts, on_option,
        on_arg, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    //Minimum two policies needed to be specified for compounding
    if (ctx.policy_list.count < 1) {
        LOG_ERR("Must specify at least 2 policy digests for compounding.");
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

    /* Policy digest hash alg should match that of the session */
    if (ctx.policy_list.digests[0].size
            != tpm2_alg_util_get_hash_size(
                    tpm2_session_get_authhash(ctx.session))) {
        LOG_ERR("Policy digest hash alg should match that of the session.");
        return tool_rc_general_error;
    }

    rc = tpm2_policy_build_policyor(ectx, ctx.session, &ctx.policy_list);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policyor TPM");
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
TPM2_TOOL_REGISTER("policyor", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
