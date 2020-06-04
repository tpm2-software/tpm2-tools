/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

typedef struct changeauth_ctx changeauth_ctx;
struct changeauth_ctx {

    struct {
        const char *ctx;
        tpm2_loaded_object obj;
    } parent;

    struct {
        const char *auth_current;
        const char *auth_new;
        const char *ctx;
        tpm2_loaded_object obj;
        tpm2_session *new;
        const char *out_path;
    } object;

    char *cp_hash_path;
};

static changeauth_ctx ctx;

static tool_rc hierarchy_change_auth(ESYS_CONTEXT *ectx,
        const TPM2B_AUTH *new_auth) {

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_hierarchy_change_auth(ectx, &ctx.object.obj, new_auth,
            &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    return tpm2_hierarchy_change_auth(ectx, &ctx.object.obj, new_auth, NULL);
}

static tool_rc nv_change_auth(ESYS_CONTEXT *ectx, const TPM2B_AUTH *new_auth) {

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_nv_change_auth(ectx, &ctx.object.obj, new_auth,
            &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    return tpm2_nv_change_auth(ectx, &ctx.object.obj, new_auth, NULL);
}

static tool_rc object_change_auth(ESYS_CONTEXT *ectx,
        const TPM2B_AUTH *new_auth) {

    if (!ctx.object.out_path) {
        LOG_ERR("Require private output file path option -r");
        return tool_rc_general_error;
    }

    TPM2B_PRIVATE *out_private = NULL;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_object_change_auth(ectx, &ctx.parent.obj, &ctx.object.obj,
            new_auth, &out_private, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    tool_rc rc = tpm2_object_change_auth(ectx, &ctx.parent.obj, &ctx.object.obj,
            new_auth, &out_private, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool res = files_save_private(out_private, ctx.object.out_path);
    free(out_private);

    return res ? tool_rc_success : tool_rc_general_error;
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
        /*no default */
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected 1 new password argument, got: %d", argc);
        return false;
    }

    ctx.object.auth_new = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    struct option topts[] = {
        { "object-auth",    required_argument, NULL, 'p' },
        { "object-context", required_argument, NULL, 'c' },
        { "parent-context", required_argument, NULL, 'C' },
        { "private",        required_argument, NULL, 'r' },
         {"cphash",         required_argument, NULL,  0  },
    };
    *opts = tpm2_options_new("p:c:C:r:", ARRAY_LEN(topts), topts,
                             on_option, on_arg, 0);

    return *opts != NULL;
}

static inline bool object_needs_parent(tpm2_loaded_object *obj) {

    TPM2_HC h = obj->handle & TPM2_HR_RANGE_MASK;
    return (h == TPM2_HR_TRANSIENT) || (h == TPM2_HR_PERSISTENT);
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /* load the object to call changeauth on */
    if (!ctx.object.ctx) {
        LOG_ERR("Expected object information via -c");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.object.ctx,
            ctx.object.auth_current, &ctx.object.obj, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.object.obj.tr_handle == ESYS_TR_RH_NULL) {
        LOG_ERR("Cannot change the null hierarchy authorization");
        return tool_rc_general_error;
    }

    /* transient objects or persistent objects need parents */
    bool load_parent = object_needs_parent(&ctx.object.obj);
    if (load_parent) {

        if (!ctx.parent.ctx) {
            LOG_ERR("Expected parent object information via -C");
            return tool_rc_option_error;
        }

        rc = tpm2_util_object_load(ectx, ctx.parent.ctx, &ctx.parent.obj,
                TPM2_HANDLE_ALL_W_NV);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    rc = tpm2_auth_util_from_optarg(ectx, ctx.object.auth_new, &ctx.object.new,
            true);
    if (rc != tool_rc_success) {
        return rc;
    }

    const TPM2B_AUTH *new_auth = tpm2_session_get_auth_value(ctx.object.new);

    /* invoke the proper changauth command based on object type */
    UINT8 tag = (ctx.object.obj.handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT;
    switch (tag) {
    case TPM2_HT_TRANSIENT:
    case TPM2_HT_PERSISTENT:
        rc = object_change_auth(ectx, new_auth);
        break;
    case TPM2_HT_NV_INDEX:
        rc = nv_change_auth(ectx, new_auth);
        break;
    case TPM2_HT_PERMANENT:
        rc = hierarchy_change_auth(ectx, new_auth);
        break;
    default:
        LOG_ERR("Unsupported object type, got: 0x%x", tag);
        rc = tool_rc_general_error;
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    tool_rc rc = tool_rc_success;

    tool_rc tmp = tpm2_session_close(&ctx.object.new);
    if (tmp != tool_rc_success) {
        rc = tmp;
    }

    tmp = tpm2_session_close(&ctx.object.obj.session);
    if (tmp != tool_rc_success) {
        rc = tmp;
    }

    tmp = tpm2_session_close(&ctx.parent.obj.session);
    if (tmp != tool_rc_success) {
        rc = tmp;
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("changeauth", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
