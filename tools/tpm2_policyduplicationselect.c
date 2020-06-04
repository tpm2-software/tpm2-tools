/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policyduplicationselect_ctx tpm2_policyduplicationselect_ctx;
struct tpm2_policyduplicationselect_ctx {
    const char *session_path;
    const char *obj_name_path;
    const char *new_parent_name_path;
    const char *out_policy_dgst_path;
    TPMI_YES_NO is_include_obj;
    TPM2B_DIGEST *policy_digest;
    tpm2_session *session;
};

static tpm2_policyduplicationselect_ctx ctx;

static bool on_option(char key, char *value) {

    ctx.is_include_obj = 0;
    switch (key) {
    case 'S':
        ctx.session_path = value;
        break;
    case 'n':
        ctx.obj_name_path = value;
        break;
    case 'N':
        ctx.new_parent_name_path = value;
        break;
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    case 0:
        ctx.is_include_obj = 1;
        break;
    }
    return true;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.new_parent_name_path) {
        LOG_ERR("Must specify -N object new parent file.");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "session",            required_argument,  NULL,   'S' },
        { "object-name",        required_argument,  NULL,   'n' },
        { "parent-name",        required_argument,  NULL,   'N' },
        { "policy",             required_argument,  NULL,   'L' },
        { "include-object",     no_argument,        NULL,    0  },
    };

    *opts = tpm2_options_new("S:n:N:L:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

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
        return rc;
    }

    rc = tpm2_policy_build_policyduplicationselect(ectx, ctx.session,
            ctx.obj_name_path, ctx.new_parent_name_path, ctx.is_include_obj);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build TPM policy_duplication_select");
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
TPM2_TOOL_REGISTER("policyduplicationselect", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
