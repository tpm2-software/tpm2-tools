/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2
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
    TPM2B_NAME precalc_nvname;
    bool has_policy_delete_set;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_command_dispatch;
    bool is_tcti_none;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_nvundefine_ctx ctx = {
    .auth_hierarchy.ctx_path = "owner",
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
};

static tool_rc nv_undefine(ESYS_CONTEXT *ectx) {

    tool_rc rc = ctx.has_policy_delete_set ?

        tpm2_nvundefinespecial(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            &ctx.precalc_nvname, ctx.policy_session.session, &ctx.cp_hash,
            &ctx.rp_hash, ctx.parameter_hash_algorithm,
            ctx.aux_session_handle[0]) :

        tpm2_nvundefine(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            &ctx.precalc_nvname, &ctx.cp_hash, &ctx.rp_hash,
            ctx.parameter_hash_algorithm, ctx.aux_session_handle[0],
            ctx.aux_session_handle[1]);

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
    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
        rc = is_file_op_success ? tool_rc_success : tool_rc_general_error;
    }

    return rc;
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
    tool_rc rc = tool_rc_success;
    tpm2_handle_flags valid_handles =
        TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P;
    if (ctx.is_tcti_none) {
         rc = tpm2_util_handle_from_optarg(ctx.auth_hierarchy.ctx_path,
             &ctx.auth_hierarchy.object.handle, valid_handles) ?
             tool_rc_success : tool_rc_option_error;

         ctx.auth_hierarchy.object.tr_handle = (rc == tool_rc_success) ?
            tpm2_tpmi_hierarchy_to_esys_tr(ctx.auth_hierarchy.object.handle) : 0;
     } else {
         rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
             ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
             valid_handles);
     }

    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle or authorization.");
        return rc;
    }

    /*
     * Object #2
     *
     * Must be a policy session satisfying the ADMIN role with policycommandcode
     * TPM2_CC_NV_UndefineSpaceSpecial
     */
    if (ctx.has_policy_delete_set && !ctx.is_tcti_none) {
        rc = tpm2_session_restore(ectx, ctx.policy_session.path, false,
                &ctx.policy_session.session);
        if (rc != tool_rc_success) {
            return rc;
        }

        /*
         * In case of undefinespacespecial first session is expected to satisfy
         * the ADMIN role in a policycommandcode session.
         */
        TPM2_SE type = tpm2_session_get_type(ctx.policy_session.session);
        if (ctx.has_policy_delete_set && type != TPM2_SE_POLICY) {
            LOG_ERR("Expected a policy session when NV index has attribute"
                    " TPMA_NV_POLICY_DELETE set. Also note that "
                    "the policy session must be specified first with -S");
            return tool_rc_option_error;
        }

        /*
         * Adjust aux session structure to reflect the only allowed additional
         * aux structure.
         */
        ctx.aux_session_cnt-=1;
        ctx.aux_session_path[0] = ctx.aux_session_path[1];
        ctx.aux_session_path[1] = 0;
    }

    /*
     * 2. Restore auxiliary sessions
     */
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }
    /*
     * 3. Command specific initializations
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *is_undefinespecial_session = ctx.has_policy_delete_set ?
        ctx.policy_session.session : ctx.aux_session[0];

    tpm2_session *last_aux_session = ctx.has_policy_delete_set ?
        ctx.aux_session[0] : ctx.aux_session[1];

    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
        is_undefinespecial_session,
        last_aux_session,
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    ctx.is_tcti_none = flags.tcti_none ? true : false;
    if (ctx.is_tcti_none && !ctx.cp_hash_path) {
        LOG_ERR("If tcti is none, then cpHash path must be specified");
        return tool_rc_option_error;
    }

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * is_tcti_none       [N]
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.is_tcti_none ||
        (ctx.cp_hash_path && !ctx.rp_hash_path)) ? false : true;

    /*
     * Peculiar to this and some other tools, the object (nvindex) name must
     * be specified when only calculating the cpHash.
     *
     * This breaks the compatibility with the 4.X tools where in a real tcti
     * is invoked to get a sapi handle to retrieve the params. Also this would
     * imply that a real NV index ought to be defined even in the case of simply
     * calculating the cpHash.
     *
     * To solve this conundrum, we can only mandate the requirement for the NV
     * index name in case tcti is specified as none. If tcti is not specified as
     * none we fall back to the old behavior of reading from a define NV index
     * 
     * Also, tcti is setup to a fake_tcti when tcti is specified "none" as the
     * tool option affords TPM2_OPTIONS_FAKE_TCTI.
     * 
     * If NVindex name is not specified and tcti is not none, it is expected
     * that the NV index is actually define. This behavior complies with the
     * backwards compatibility with 4.X
     */
    bool is_nv_name_specified = ctx.precalc_nvname.size;
    if (ctx.is_tcti_none && !is_nv_name_specified) {
        LOG_ERR("Must specify the NVIndex name.");
        return tool_rc_option_error;
    }

    if (!ctx.is_tcti_none && is_nv_name_specified) {
        LOG_ERR("Do not specify NVIndex name, it is directly read from NV");
        return tool_rc_option_error;
    }

    bool is_platform_hierarchy_required = ctx.has_policy_delete_set;
    if (!ctx.is_tcti_none) {
        /*
         * Read the public portion of the NV index so we can ascertain if
         * TPMA_NV_POLICYDELETE is set. This determines which command to use
         * to undefine the space. Either undefine or undefinespecial.
         */
        TPM2B_NV_PUBLIC *nv_public = NULL;
        tool_rc rc = tpm2_util_nv_read_public(ectx, ctx.nv_index, 0, &nv_public,
            0, 0, 0, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to read the public part of NV index 0x%X", ctx.nv_index);
            return rc;
        }

        if (ctx.has_policy_delete_set &&
        !(nv_public->nvPublic.attributes & TPMA_NV_POLICY_DELETE)) {
            LOG_ERR("Specified --with-policydelete but NV index attribute not set");
            return tool_rc_option_error;
        }
        ctx.has_policy_delete_set =
            nv_public->nvPublic.attributes & TPMA_NV_POLICY_DELETE;

        is_platform_hierarchy_required = ctx.has_policy_delete_set ||
            (nv_public->nvPublic.attributes & TPMA_NV_PLATFORMCREATE);

        Esys_Free(nv_public);
    }

    /*
     * When calculating cpHash with tcti=none, assumption is that the auth
     * hierarchy will be specified as TPM2_RH_PLATFORM. Note that the default
     * setting for auth hierarchy is TPM2_RH_OWNER.
     */
    if (!ctx.is_auth_hierarchy_specified && is_platform_hierarchy_required) {
        ctx.auth_hierarchy.ctx_path = "platform";
    }

    if (!ctx.is_tcti_none &&
    (ctx.has_policy_delete_set && !ctx.policy_session.path)) {
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
        /*
         * In case of undefinespacespecial first session is expected to satisfy
         * the ADMIN role in a policycommandcode session.
         */
        if (!ctx.aux_session_cnt) {
            ctx.policy_session.path = value;   
        }
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.rp_hash_path = value;
        break;
    case 2:
        ctx.has_policy_delete_set = true;
        break;
    case 'n':
        ctx.precalc_nvname.size = BUFFER_SIZE(TPM2B_NAME, name);
        int q = tpm2_util_hex_to_byte_structure(value, &ctx.precalc_nvname.size,
        ctx.precalc_nvname.name);
        if (q) {
            LOG_ERR("FAILED: %d", q);
            return false;
        }
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
        { "hierarchy",          required_argument, NULL, 'C' },
        { "auth",               required_argument, NULL, 'P' },
        { "session",            required_argument, NULL, 'S' },
        { "cphash",             required_argument, NULL,  0  },
        { "rphash",             required_argument, NULL,  1  },
        { "with-policydelete",  no_argument,       NULL,  2  },
        { "name",               required_argument, NULL, 'n' },
    };

    *opts = tpm2_options_new("C:P:S:n:", ARRAY_LEN(topts), topts, on_option,
        on_arg, TPM2_OPTIONS_FAKE_TCTI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx, flags);
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
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvundefine", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
