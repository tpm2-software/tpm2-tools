/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"

typedef struct tpm_nvundefine_ctx tpm_nvundefine_ctx;
struct tpm_nvundefine_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    struct {
        const char *path;
        tpm2_session *session;
    } policy_session;

    struct {
        bool C;
    } flags;

    TPM2_HANDLE nv_index;

    char *cp_hash_path;
};

static tpm_nvundefine_ctx ctx = {
    .auth_hierarchy.ctx_path = "owner",
};

static bool on_option(char key, char *value) {

    switch (key) {

    case 'C':
        ctx.flags.C = true;
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'S':
        ctx.policy_session.path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "auth",      required_argument, NULL, 'P' },
        { "session",   required_argument, NULL, 'S' },
        { "cphash",    required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:P:S:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * Read the public portion of the NV index so we can ascertain if
     * TPMA_NV_POLICYDELETE is set. This determines which command to use
     * to undefine the space. Either undefine or undefinespecial.
     */
    TPM2B_NV_PUBLIC *nv_public = NULL;
    tool_rc rc = tpm2_util_nv_read_public(ectx, ctx.nv_index, &nv_public);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to read the public part of NV index 0x%X", ctx.nv_index);
        return rc;
    }

    bool has_policy_delete_set = !!(nv_public->nvPublic.attributes & TPMA_NV_POLICY_DELETE);

    Esys_Free(nv_public);

    /*
     * The default hierarchy is typically owner, however with a policy delete object it's always
     * the platform.
     */
    if (!ctx.flags.C) {
        ctx.auth_hierarchy.ctx_path  = has_policy_delete_set ? "platform" : "owner";
    }

    /* now with the default sorted out, load the authorization object */
    rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    bool result = true;
    TPM2B_DIGEST cp_hash = { .size = 0 };
    /* has policy delete set, so do NV undefine special */
    if (has_policy_delete_set) {

        if (!ctx.policy_session.path) {
            LOG_ERR("NV Spaces with attribute TPMA_NV_POLICY_DELETE require a"
                    " policy session to be specified via \"-S\"");
            return tool_rc_general_error;
        }

        rc = tpm2_session_restore(ectx, ctx.policy_session.path, false,
                &ctx.policy_session.session);
        if (rc != tool_rc_success) {
            return rc;
        }

        /*
         * has to be an admin policy session for undefinespecial.
         * We can at least check that it is a session.
         */
        TPM2_SE type = tpm2_session_get_type(ctx.policy_session.session);
        if (type != TPM2_SE_POLICY) {
            LOG_ERR("Expected a policy session when NV index has attribute"
                    " TPMA_NV_POLICY_DELETE set.");
            return tool_rc_general_error;
        }

        if (!ctx.cp_hash_path) {
            return tpm2_nvundefinespecial(ectx, &ctx.auth_hierarchy.object,
                ctx.nv_index, ctx.policy_session.session, NULL);
        }

        rc = tpm2_nvundefinespecial(ectx, &ctx.auth_hierarchy.object,
                ctx.nv_index, ctx.policy_session.session, &cp_hash);;
        if (rc != tool_rc_success) {
            return rc;
        }
        goto nvundefine_out;
    }

    if (ctx.policy_session.path && !has_policy_delete_set) {
       LOG_WARN("Option -S is not required on NV indices that don't have"
               " attribute TPMA_NV_POLICY_DELETE set");
    }

    if (!ctx.cp_hash_path) {
        return tpm2_nvundefine(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            NULL);
    }

    rc = tpm2_nvundefine(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
        &cp_hash);;
    if (rc != tool_rc_success) {
        return rc;
    }

nvundefine_out:
    result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    /* attempt to close all sessions and report errors */
    tool_rc rc = tool_rc_success;
    if (!ctx.cp_hash_path) {
        rc = tpm2_session_close(&ctx.policy_session.session);
        rc |= tpm2_session_close(&ctx.auth_hierarchy.object.session);
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvundefine", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
