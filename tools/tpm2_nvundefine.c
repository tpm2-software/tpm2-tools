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
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    struct {
        const char *path;
        tpm2_session *session;
    } policy_session;

    bool is_auth_hierarchy_specified;

    TPM2_HANDLE nv_index;
    bool has_policy_delete_set;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    char *cp_hash_path;
    TPM2B_DIGEST *cphash;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
};

static tpm_nvundefine_ctx ctx = {
    .auth_hierarchy.ctx_path = "owner",
};

static tool_rc nv_undefine(ESYS_CONTEXT *ectx) {

    tool_rc rc = ctx.has_policy_delete_set ?

        tpm2_nvundefinespecial(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            ctx.policy_session.session, ctx.cphash) :

        tpm2_nvundefine(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            ctx.cphash);

    return rc;
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    return tool_rc_success;
}


static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
        ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
        TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    /* Object #2 #/
    /*
     * has to be an admin policy session for undefinespecial.
     * We can at least check that it is a session.
     */
    if (ctx.has_policy_delete_set) {
        rc = tpm2_session_restore(ectx, ctx.policy_session.path, false,
                &ctx.policy_session.session);
        if (rc != tool_rc_success) {
            return rc;
        }

        TPM2_SE type = tpm2_session_get_type(ctx.policy_session.session);
        if (ctx.has_policy_delete_set && type != TPM2_SE_POLICY) {
            LOG_ERR("Expected a policy session when NV index has attribute"
                    " TPMA_NV_POLICY_DELETE set.");
            return tool_rc_option_error;
        }
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    ctx.cphash = ctx.cp_hash_path ? &ctx.cp_hash : 0;

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

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

    ctx.has_policy_delete_set =
        nv_public->nvPublic.attributes & TPMA_NV_POLICY_DELETE;

    bool is_platform_hierarchy_required = ctx.has_policy_delete_set ||
        (nv_public->nvPublic.attributes & TPMA_NV_PLATFORMCREATE);

    Esys_Free(nv_public);

    if (!ctx.is_auth_hierarchy_specified && is_platform_hierarchy_required) {
        ctx.auth_hierarchy.ctx_path = "platform";
    }

    if (ctx.has_policy_delete_set && !ctx.policy_session.path) {
        LOG_ERR("NV Spaces with attribute TPMA_NV_POLICY_DELETE require a "
                "policy session to be specified via \"-S\"");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {
    /*
     * If the user doesn't specify an authorization hierarchy use the index
     */
    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.is_auth_hierarchy_specified = true;
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

static bool tpm2_tool_onstart(tpm2_options **opts) {
/*
 * The tool does both undefine and undefine space special and so the options
 * are interpreted accordingly.
 * 
 * Case NV_Undefine:
 *       1. 'C' and 'P' correspond to either TPM2_RH_OWNER or TPM2_RH_PLATFORM
 *       2. In this case, two aux sessions are allowed.
 * Case NV_UndefineSpaceSpecial:
 *       1. 'S' is for the NV-Index --> Object#1, Session#1.
 *       2. 'C' and 'P' is defaulted to TPM2_RH_PLATFORM --> Object#2, Session#2
 *       3. In this case, just one aux session is allowed.
 *       4. Additional option --with-policydelete is required with tcti=none as
 *          the NV index isn't available to read the attribute when only
 *          calculating cpHash and command is not dispatched.
 */
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
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = nv_undefine(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.policy_session.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvundefine", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
