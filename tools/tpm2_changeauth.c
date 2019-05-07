/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct auth auth;
struct auth {
    tpm2_session *old;
    tpm2_session *new;
};

typedef struct changeauth_ctx changeauth_ctx;
struct changeauth_ctx {
    struct {
        auth owner;
        auth endorse;
        auth lockout;
        auth tpm_handle;
    } auths;
    struct {
        UINT8 w : 1;
        UINT8 e : 1;
        UINT8 l : 1;
        UINT8 W : 1;
        UINT8 E : 1;
        UINT8 L : 1;
        UINT8 p : 1;
        UINT8 P : 1;
        UINT8 c : 1;
        UINT8 C : 1;
        UINT8 r : 1;
    } flags;
    char *owner_auth_str;
    char *owner_auth_old_str;
    char *endorse_auth_str;
    char *endorse_auth_old_str;
    char *lockout_auth_str;
    char *lockout_auth_old_str;
    char *tpm_handle_auth_str;
    char *tpm_handle_auth_old_str;
    bool is_nv;
    bool is_transient;
    bool is_persistent;
    const char *tpm_handle_context_arg;
    tpm2_loaded_object tpm_handle_context_object;
    char *opr_path;
    const char *tpm_handle_parent_context_arg;
    tpm2_loaded_object tpm_handle_parent_context_object;
};

static changeauth_ctx ctx;

static bool change_auth(ESYS_CONTEXT *ectx,
        struct auth *pwd, const char *desc,
        ESYS_TR auth_handle) {

    TSS2_RC rval;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, auth_handle,
                            pwd->old);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle for auth");
        return false;
    }

    const TPM2B_AUTH *new_auth = tpm2_session_get_auth_value(pwd->new);

    rval = Esys_HierarchyChangeAuth(ectx, auth_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                new_auth);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_HierarchyChangeAuth, rval);
        return false;
    }

    LOG_INFO("Successfully changed hierarchy for %s", desc);

    return true;
}

static bool change_hierarchy_auth(ESYS_CONTEXT *ectx) {

    // change owner, endorsement and lockout auth.
    bool result = true;
    if (ctx.flags.w || ctx.flags.W) {
        result &= change_auth(ectx, &ctx.auths.owner,
                "Owner", ESYS_TR_RH_OWNER);
    }

    if (ctx.flags.e || ctx.flags.E) {
        result &= change_auth(ectx, &ctx.auths.endorse,
                "Endorsement", ESYS_TR_RH_ENDORSEMENT);
    }

    if (ctx.flags.l || ctx.flags.L) {
        result &= change_auth(ectx, &ctx.auths.lockout,
                "Lockout", ESYS_TR_RH_LOCKOUT);
    }

    return result;
}


static bool process_change_hierarchy_auth (ESYS_CONTEXT *ectx) {

    /* always run this, so we pick up the default empty password session */
    bool result = tpm2_auth_util_from_optarg(NULL, ctx.owner_auth_str,
            &ctx.auths.owner.new, true);
    if (!result) {
        LOG_ERR("Invalid new owner authorization, got\"%s\"", ctx.owner_auth_str);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(NULL, ctx.endorse_auth_str,
            &ctx.auths.endorse.new, true);
    if (!result) {
        LOG_ERR("Invalid new endorse authorization, got\"%s\"",
            ctx.endorse_auth_str);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(NULL, ctx.lockout_auth_str,
            &ctx.auths.lockout.new, true);
    if (!result) {
        LOG_ERR("Invalid new lockout authorization, got\"%s\"",
            ctx.lockout_auth_str);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.owner_auth_old_str,
            &ctx.auths.owner.old, false);
    if (!result) {
        LOG_ERR("Invalid current owner authorization, got\"%s\"",
            ctx.owner_auth_old_str);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.endorse_auth_old_str,
            &ctx.auths.endorse.old, false);
    if (!result) {
        LOG_ERR("Invalid current endorse authorization, got\"%s\"",
            ctx.endorse_auth_old_str);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.lockout_auth_old_str,
            &ctx.auths.lockout.old, false);
    if (!result) {
        LOG_ERR("Invalid current lockout authorization, got\"%s\"",
            ctx.lockout_auth_old_str);
        goto out;
    }

    result = change_hierarchy_auth(ectx);

out:
    result &= tpm2_session_close(&ctx.auths.endorse.old);
    result &= tpm2_session_close(&ctx.auths.owner.old);
    result &= tpm2_session_close(&ctx.auths.lockout.old);

    return result;
}

static bool process_tpm_handle_auths(ESYS_CONTEXT *ectx) {

    /* always run this, so we pick up the default empty password session */
    bool result = tpm2_auth_util_from_optarg(ectx, ctx.tpm_handle_auth_str,
                &ctx.auths.tpm_handle.new, true);
    if (!result) {
        LOG_ERR("Invalid new authorization for tpm handle, got\"%s\"",
            ctx.tpm_handle_auth_str);
        return false;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.tpm_handle_auth_old_str,
            &ctx.auths.tpm_handle.old, false);
    if (!result) {
        LOG_ERR("Invalid current authorization for tpm handle, got\"%s\"",
            ctx.tpm_handle_auth_old_str);
        return false;
    }

    return true;
}

static bool process_change_nv_handle_auth(ESYS_CONTEXT *ectx) {

    bool result = false;

    bool ret = process_tpm_handle_auths(ectx);
    if (!ret) {
        goto out;
    }

    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx,
                        ctx.tpm_handle_context_object.tr_handle,
                        ctx.auths.tpm_handle.old);
    if (shandle == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        goto out;
    }

    const TPM2B_AUTH *new_auth = tpm2_session_get_auth_value(ctx.auths.tpm_handle.new);

    TSS2_RC rval = Esys_NV_ChangeAuth(ectx,
                    ctx.tpm_handle_context_object.tr_handle,
                    shandle, ESYS_TR_NONE, ESYS_TR_NONE, new_auth);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ChangeAuth, rval);
        goto out;
    }

    result = true;

out:
    result &= tpm2_session_close(&ctx.auths.tpm_handle.old);

    return result;
}

static bool process_change_tpm_handle_auth(ESYS_CONTEXT *ectx) {

    bool result = false;
    TPM2B_PRIVATE *outPrivate = NULL;

    bool ret = process_tpm_handle_auths(ectx);
    if (!ret) {
        goto out;
    }

    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx,
                        ctx.tpm_handle_context_object.tr_handle,
                        ctx.auths.tpm_handle.old);
    if (shandle == ESYS_TR_NONE) {
        goto out;
    }

    if (!ctx.tpm_handle_parent_context_object.tr_handle) {
        result = tpm2_util_sys_handle_to_esys_handle(
                ectx,
                ctx.tpm_handle_parent_context_object.handle,
                &ctx.tpm_handle_parent_context_object.tr_handle);
        if (!result) {
            goto out;
        }
    }

    const TPM2B_AUTH *new_auth = tpm2_session_get_auth_value(ctx.auths.tpm_handle.new);

    TSS2_RC rval = Esys_ObjectChangeAuth(ectx,
                        ctx.tpm_handle_context_object.tr_handle,
                        ctx.tpm_handle_parent_context_object.tr_handle,
                        shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                        new_auth, &outPrivate);

    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ObjectChangeAuth, rval);
        goto out;
    }

    if (ctx.flags.r) {
        bool res = files_save_private(outPrivate, ctx.opr_path);
        if (!res) {
            goto out;
        }
    }

    result = true;

out:
    result &= tpm2_session_close(&ctx.auths.tpm_handle.old);
    free(outPrivate);

    return result;
}

static bool on_option(char key, char *value) {

    switch (key) {

    case 'w':
        ctx.flags.w = 1;
        ctx.owner_auth_str = value;
        break;
    case 'e':
        ctx.flags.e = 1;
        ctx.endorse_auth_str = value;
        break;
    case 'l':
        ctx.flags.l = 1;
        ctx.lockout_auth_str = value;
        break;
    case 'W':
        ctx.flags.W = 1;
        ctx.owner_auth_old_str = value;
        break;
    case 'E':
        ctx.flags.E = 1;
        ctx.endorse_auth_old_str = value;
        break;
    case 'L':
        ctx.flags.L = 1;
        ctx.lockout_auth_old_str = value;
        break;
    case 'c':
        ctx.flags.c = 1;
        ctx.tpm_handle_context_arg = value;
        break;
    case 'C':
        ctx.flags.C = 1;
        ctx.tpm_handle_parent_context_arg = value;
        break;
    case 'p':
        ctx.flags.p = 1;
        ctx.tpm_handle_auth_str = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.tpm_handle_auth_old_str = value;
        break;
    case 'r':
        ctx.opr_path = value;
        ctx.flags.r = 1;
        break;
        /*no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    struct option topts[] = {
        //Special Permanent Handles: OWNER/ ENDORSEMENT/ LOCKOUT
        { "new-auth-owner",             required_argument, NULL, 'w' },
        { "current-auth-owner",         required_argument, NULL, 'W' },
        { "new-auth-endorse",           required_argument, NULL, 'e' },
        { "current-auth-endorse",       required_argument, NULL, 'E' },
        { "new-auth-lockout",           required_argument, NULL, 'l' },
        { "current-auth-lockout",       required_argument, NULL, 'L' },
        //Other TPM Handles: PERSISTENT/ TRANSIENT/ NV
        { "new-auth-handle",            required_argument, NULL, 'p' },
        { "current-auth-handle",        required_argument, NULL, 'P' },
        { "key-context",                required_argument, NULL, 'c' },
        //Additional parameters for PERSISTENT/ TRANSIENT Handles:
        { "key-parent-context",         required_argument, NULL, 'C' },
        { "privfile",                   required_argument, NULL, 'r' },
    };
    *opts = tpm2_options_new("w:e:l:W:E:L:p:P:c:C:r:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (ctx.flags.c) {
        switch((ctx.tpm_handle_context_object.handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT) {
            case TPM2_HT_TRANSIENT:
                ctx.is_transient = true;
                break;
            case TPM2_HT_PERSISTENT:
                ctx.is_persistent = true;
                break;
            case TPM2_HT_NV_INDEX:
                ctx.is_nv = true;
                break;
            default:
                // transient objects are only specified via file context and thus
                // have no handle just an ESYS_TR
                ctx.is_transient = true;
        }
    }

    /*
     * Handle specified without any intended operation
     */
    if (!ctx.flags.P && !ctx.flags.p && ctx.flags.c) {
        LOG_ERR("Must specify the handle/context auths for set/modify operation.");
        return false;
    }

    /*
     * Clear auth value of an object --> ctx.flags.p = 0
     * Set auth for an object that had no auth --> ctx.flags.P = 0
     * Change old auth value to new auth value --> ctx.flags.p == ctx.flags.P = 1
     */
    if ((ctx.flags.P || ctx.flags.P) && !ctx.flags.c) {
        LOG_ERR("Must specify the handle/context for auth change.");
        return false;
    }

    if ((ctx.is_persistent || ctx.is_transient) && (!ctx.flags.C || !ctx.flags.r)) {
        LOG_ERR("Must specify the parent handle/context of the key whose auth "
         "is being changed along with the path to save the new sensitive data");
        return false;
    }

    if ((ctx.is_persistent || ctx.is_transient) && ctx.is_nv) {
        LOG_ERR("Specify a transient/persistent handle OR a NV Index, not both.");
        return false;
    }

    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result;
    if (ctx.flags.c) {
        bool result = tpm2_util_object_load(ectx, ctx.tpm_handle_context_arg,
                &ctx.tpm_handle_context_object);
        if (!result) {
            LOG_ERR("Invalid TPM object handle");
            return -1;
        }
    }

    if (ctx.flags.C) {
        bool result = tpm2_util_object_load(ectx, ctx.tpm_handle_parent_context_arg,
                &ctx.tpm_handle_parent_context_object);
        if (!result) {
            LOG_ERR("Invalid TPM object handle parent");
            return -1;
        }
    }

    result = is_input_option_args_valid();
    if (!result) {
        return -1;
    }

    if (ctx.is_persistent || ctx.is_transient) {
        result = process_change_tpm_handle_auth(ectx);
    }

    if (ctx.is_nv) {
        result = process_change_nv_handle_auth(ectx);
    }

    if (ctx.flags.w || ctx.flags.e || ctx.flags.l || ctx.flags.W || ctx.flags.E
            || ctx.flags.L) {
        result = process_change_hierarchy_auth(ectx);
    }

    /* true is success, coerce to 0 for program success */
    return result == false;
}
