/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "tpm2.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"

typedef struct tpm_policyauthorizenv_ctx tpm_policyauthorizenv_ctx;
struct tpm_policyauthorizenv_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;

    const char *out_policy_dgst_path;

    const char *session_path;
    tpm2_session *session;
};

static tpm_policyauthorizenv_ctx ctx;

static bool on_arg(int argc, char **argv) {
    /* If the user doesn't specify an authorization hierarchy use the index
     * passed to -x/--index for the authorization index.
     */
    if (!ctx.auth_hierarchy.ctx_path) {
        ctx.auth_hierarchy.ctx_path = argv[0];
    }
    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool on_option(char key, char *value) {

    switch (key) {

    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    default:
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "auth",      required_argument, NULL, 'P' },
        { "policy",    required_argument, NULL, 'L' },
        { "session",   required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("C:P:L:S:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }
    return true;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    rc = tpm2_session_restore(ectx, ctx.session_path, false, &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    ESYS_TR policy_session_handle = tpm2_session_get_handle(ctx.session);

    rc = tpm2_policy_authorize_nv(ectx, &ctx.auth_hierarchy.object,
        ctx.nv_index, policy_session_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.out_policy_dgst_path);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}
