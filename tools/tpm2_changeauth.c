/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

typedef struct changeauth_ctx changeauth_ctx;
#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2 // It's possible that parent auth may not be needed
struct changeauth_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx;
        tpm2_loaded_object obj;
    } parent;

    bool autoflush;

    struct {
        const char *auth_current;
        const char *auth_new;
        const char *ctx;
        tpm2_loaded_object obj;
        tpm2_session *new;

    /*
     * Outputs
     */
        const char *out_path;
    } object;
    TPM2B_PRIVATE *out_private;
    const TPM2B_AUTH *new_auth;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static changeauth_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
    .autoflush = false,
};

static tool_rc hierarchy_change_auth(ESYS_CONTEXT *ectx) {

    return tpm2_hierarchy_change_auth(ectx, &ctx.object.obj, ctx.new_auth,
        &ctx.cp_hash, &ctx.rp_hash, ctx.parameter_hash_algorithm,
        ctx.aux_session_handle[0], ctx.aux_session_handle[1]);
}

static tool_rc nv_change_auth(ESYS_CONTEXT *ectx) {

    return tpm2_nv_change_auth(ectx, &ctx.object.obj, ctx.new_auth,
        &ctx.cp_hash, &ctx.rp_hash, ctx.parameter_hash_algorithm,
        ctx.aux_session_handle[0], ctx.aux_session_handle[1]);
}

static tool_rc object_change_auth(ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    if (!ctx.object.out_path) {
        LOG_ERR("Require private output file path option -r");
        return tool_rc_general_error;
    }

    tool_rc rc = tpm2_object_change_auth(ectx, &ctx.parent.obj, &ctx.object.obj,
        ctx.new_auth, &ctx.out_private, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0],
        ctx.aux_session_handle[1]);
    if (rc != tool_rc_success) {
            return rc;
    }
    if ((ctx.autoflush || tpm2_util_env_yes(TPM2TOOLS_ENV_AUTOFLUSH)) &&
        ctx.parent.obj.path &&
        (ctx.parent.obj.handle & TPM2_HR_RANGE_MASK) == TPM2_HR_TRANSIENT) {
        rval = Esys_FlushContext(ectx, ctx.parent.obj.tr_handle);
        if (rval != TPM2_RC_SUCCESS) {
            return tool_rc_general_error;
        }
    }
    return tool_rc_success;
}

static tool_rc change_authorization(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */

    tool_rc rc = tool_rc_success;

    /* invoke the proper changauth command based on object type */
    UINT8 tag = (ctx.object.obj.handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT;
    switch (tag) {
    case TPM2_HT_TRANSIENT:
    case TPM2_HT_PERSISTENT:
        rc = object_change_auth(ectx);
        break;
    case TPM2_HT_NV_INDEX:
        rc = nv_change_auth(ectx);
        break;
    case TPM2_HT_PERMANENT:
        rc = hierarchy_change_auth(ectx);
        break;
    default:
        LOG_ERR("Unsupported object type, got: 0x%x", tag);
        rc = tool_rc_general_error;
    }

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

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    if (ctx.is_command_dispatch && ctx.out_private) {
        is_file_op_success = files_save_private(ctx.out_private,
            ctx.object.out_path);
        free(ctx.out_private);

        if (!is_file_op_success) {
            LOG_ERR("Failed to save the sensitive key portion");
            return tool_rc_general_error;
        }
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}

static inline bool object_needs_parent(tpm2_loaded_object *obj) {

    TPM2_HC h = obj->handle & TPM2_HR_RANGE_MASK;
    return (h == TPM2_HR_TRANSIENT) || (h == TPM2_HR_PERSISTENT);
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */
    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.object.auth_new,
        &ctx.object.new, true);
    if (rc != tool_rc_success) {
        return rc;
    }

    ctx.new_auth = tpm2_session_get_auth_value(ctx.object.new);

    /*
     * 1.b Add object names and their auth sessions
     */

     /* Note: Old-auth value is ignored when calculating cpHash */

    /* Object #1 */
    rc = tpm2_util_object_load_auth(ectx, ctx.object.ctx,
        ctx.object.auth_current, &ctx.object.obj, false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.object.obj.tr_handle == ESYS_TR_RH_NULL) {
        LOG_ERR("Cannot change the null hierarchy authorization");
        return tool_rc_general_error;
    }
    /* transient objects or persistent objects need parents */
    bool load_parent = object_needs_parent(&ctx.object.obj);
    if (load_parent && !ctx.parent.ctx) {
        LOG_ERR("Expected parent object information via -C");
        return tool_rc_option_error;
    }

    /* Object #2 */
    if (load_parent) {
        rc = tpm2_util_object_load(ectx, ctx.parent.ctx, &ctx.parent.obj,
            TPM2_HANDLE_ALL_W_NV);

        if (rc != tool_rc_success) {
            return rc;
        }
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
     * 3. Command specific initializations dependent on loaded objects
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /* 4.a Determine pHash length and alg */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.object.obj.session,
        ctx.aux_session[0],
        ctx.aux_session[1]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /* 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    return tool_rc_success;
}

static tool_rc check_options(void) {

    /* load the object to call changeauth on */
    if (!ctx.object.ctx) {
        LOG_ERR("Expected object information via -c");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && !ctx.rp_hash_path) {
        LOG_WARN("Auth not changed. Only cpHash is calculated.");
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected 1 new password argument, got: %d", argc);
        return false;
    }

    ctx.object.auth_new = argv[0];

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.object.ctx = value;
        break;
    case 'C':
        ctx.parent.ctx = value;
        break;
    case 'p':
        ctx.object.auth_current = value;
        break;
    case 'n':
        ctx.object.auth_new = value;
        break;
    case 'r':
        ctx.object.out_path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
        break;
    case 'R':
        ctx.autoflush = true;
        break;

        /*no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    struct option topts[] = {
        { "object-auth",    required_argument, NULL, 'p' },
        { "object-context", required_argument, NULL, 'c' },
        { "parent-context", required_argument, NULL, 'C' },
        { "private",        required_argument, NULL, 'r' },
        { "cphash",         required_argument, NULL,  0  },
        { "rphash",         required_argument, NULL,  1  },
        { "session",        required_argument, NULL, 'S' },
        { "autoflush",      no_argument,       NULL, 'R' },
    };
    *opts = tpm2_options_new("p:c:C:r:S:R", ARRAY_LEN(topts), topts,
                             on_option, on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
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
    rc = change_authorization(ectx);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.object.new);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.object.obj.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.parent.obj.session);
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
TPM2_TOOL_REGISTER("changeauth", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
