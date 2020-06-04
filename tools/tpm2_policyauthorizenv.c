/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "tpm2.h"
#include "tpm2_tool.h"
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

    char *cp_hash_path;
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
    case 0:
        ctx.cp_hash_path = value;
        break;
    default:
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "auth",      required_argument, NULL, 'P' },
        { "policy",    required_argument, NULL, 'L' },
        { "session",   required_argument, NULL, 'S' },
        { "cphash",    required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:P:L:S:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (ctx.cp_hash_path && ctx.out_policy_dgst_path) {
        LOG_WARN("Cannot output policyhash when calculating cphash.");
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

    if (!ctx.cp_hash_path) {
        rc = tpm2_policy_authorize_nv(ectx, &ctx.auth_hierarchy.object,
            ctx.nv_index, policy_session_handle, NULL);
        if (rc != tool_rc_success) {
            return rc;
        }

        return tpm2_policy_tool_finish(ectx, ctx.session,
            ctx.out_policy_dgst_path);
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = tpm2_policy_authorize_nv(ectx, &ctx.auth_hierarchy.object,
        ctx.nv_index, policy_session_handle, &cp_hash);
    if (rc != tool_rc_success) {
        goto cphash_error_out;
    }

    bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    } else {
        goto cphash_out;
    }

cphash_error_out:
    LOG_ERR("Failed cphash calculation operation");
cphash_out:
    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tool_rc_success;

    if (!ctx.cp_hash_path) {
        tmp_rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);
        if (tmp_rc != tool_rc_success) {
            rc = tmp_rc;
        }
    }
    tmp_rc = tpm2_session_close(&ctx.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policyauthorizenv", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
