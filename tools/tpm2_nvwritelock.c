/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"

typedef struct tpm_nvwritelock_ctx tpm_nvwritelock_ctx;
struct tpm_nvwritelock_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    bool global_writelock;
    bool has_nv_argument;
    TPM2_HANDLE nv_index;

    char *cp_hash_path;
};

static tpm_nvwritelock_ctx ctx;

static bool on_arg(int argc, char **argv) {
    /* If the user doesn't specify an authorization hierarchy use the index
     * passed to -x/--index for the authorization index.
     */
    if (!ctx.auth_hierarchy.ctx_path) {
        ctx.auth_hierarchy.ctx_path = argv[0];
    }

    ctx.has_nv_argument = true;

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
    case 0:
        ctx.global_writelock= true;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "auth",      required_argument, NULL, 'P' },
        { "global",    no_argument,       NULL,  0  },
        { "cphash",    required_argument, NULL,  1  },
    };

    *opts = tpm2_options_new("C:P:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tpm2_handle_flags valid_handles = TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P;

    if (!ctx.global_writelock) {
        valid_handles |= TPM2_HANDLE_FLAGS_NV;
    } else if (ctx.has_nv_argument) {
        LOG_ERR("Cannot specify nv index and --global flag");
        return tool_rc_general_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            valid_handles);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    if (!ctx.cp_hash_path) {
        return ctx.global_writelock ?
            tpm2_nvglobalwritelock(ectx, &ctx.auth_hierarchy.object, NULL) :
            tpm2_nvwritelock(ectx, &ctx.auth_hierarchy.object, ctx.nv_index, NULL);
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = ctx.global_writelock ?
         tpm2_nvglobalwritelock(ectx, &ctx.auth_hierarchy.object, &cp_hash) :
         tpm2_nvwritelock(ectx, &ctx.auth_hierarchy.object, ctx.nv_index, &cp_hash);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    if (!ctx.cp_hash_path) {
        return tpm2_session_close(&ctx.auth_hierarchy.object.session);
    }
    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvwritelock", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
