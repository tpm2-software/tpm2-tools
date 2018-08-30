//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
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
    struct {
        TPMS_AUTH_COMMAND auth;
        tpm2_session *session;
    } old;
    struct {
        TPMS_AUTH_COMMAND auth;
    } new;
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
        UINT8 o : 1;
        UINT8 e : 1;
        UINT8 l : 1;
        UINT8 O : 1;
        UINT8 E : 1;
        UINT8 L : 1;
        UINT8 p : 1;
        UINT8 P : 1;
        UINT8 c : 1;
        UINT8 a : 1;
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
    bool is_auth_policy_session_loaded;
    const char *tpm_handle_context_arg;
    tpm2_loaded_object tpm_handle_context_object;
    char *opr_path;
    const char *tpm_handle_parent_context_arg;
    tpm2_loaded_object tpm_handle_parent_context_object;
};

static changeauth_ctx ctx = {
    .auths = {
        .owner = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        },
        .endorse = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        },
        .lockout = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) }
        },
        .tpm_handle = {
            .old = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
            .new = { .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        },
    },
    .flags = { 0 },
};

static bool change_auth(ESYS_CONTEXT *ectx,
        struct auth *pwd, const char *desc,
        ESYS_TR auth_handle) {

    TSS2_RC rval;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, auth_handle,
                            &pwd->old.auth, pwd->old.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle for auth");
        return false;
    }

    rval = Esys_HierarchyChangeAuth(ectx, auth_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &pwd->new.auth.hmac);
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
    if (ctx.flags.o || ctx.flags.O) {
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

    bool result;

    if (ctx.flags.o) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.owner_auth_str,
                &ctx.auths.owner.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new owner authorization, got\"%s\"", ctx.owner_auth_str);
            return false;
        }
    }

    if (ctx.flags.e) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.endorse_auth_str,
                &ctx.auths.endorse.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new endorse authorization, got\"%s\"",
                ctx.endorse_auth_str);
            return false;
        }
    }

    if (ctx.flags.l) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.lockout_auth_str,
                &ctx.auths.lockout.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new lockout authorization, got\"%s\"",
                ctx.lockout_auth_str);
            return false;
        }
    }

    if (ctx.flags.O) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.owner_auth_old_str,
                &ctx.auths.owner.old.auth, &ctx.auths.owner.old.session);
        if (!result) {
            LOG_ERR("Invalid current owner authorization, got\"%s\"",
                ctx.owner_auth_old_str);
            return false;
        }
    }

    if (ctx.flags.E) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.endorse_auth_old_str,
                &ctx.auths.endorse.old.auth, &ctx.auths.endorse.old.session);
        if (!result) {
            LOG_ERR("Invalid current endorse authorization, got\"%s\"",
                ctx.endorse_auth_old_str);
            return false;
        }
    }

    if (ctx.flags.L) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.lockout_auth_old_str,
                &ctx.auths.lockout.old.auth, &ctx.auths.lockout.old.session);
        if (!result) {
            LOG_ERR("Invalid current lockout authorization, got\"%s\"",
                ctx.lockout_auth_old_str);
            return false;
        }
    }

    result = change_hierarchy_auth(ectx);
    result &= tpm2_session_save(ectx, ctx.auths.endorse.old.session, NULL);
    result &= tpm2_session_save(ectx, ctx.auths.owner.old.session, NULL);
    result &= tpm2_session_save(ectx, ctx.auths.lockout.old.session, NULL);

    return result;
}

static bool process_tpm_handle_auths(ESYS_CONTEXT *ectx) {

    bool result;
    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.tpm_handle_auth_str,
                &ctx.auths.tpm_handle.new.auth, NULL);
        if (!result) {
            LOG_ERR("Invalid new authorization for tpm handle, got\"%s\"",
                ctx.tpm_handle_auth_str);
            return false;
        }
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.tpm_handle_auth_old_str,
                &ctx.auths.tpm_handle.old.auth, &ctx.auths.tpm_handle.old.session);
        if (!result) {
            LOG_ERR("Invalid current authorization for tpm handle, got\"%s\"",
                ctx.tpm_handle_auth_old_str);
            return false;
        }
        if(ctx.auths.tpm_handle.old.session != NULL) {
            ctx.is_auth_policy_session_loaded = true;
        }
    }

    return true;
}

static bool process_change_nv_handle_auth(ESYS_CONTEXT *ectx) {

    bool result = process_tpm_handle_auths(ectx);
    if (!result) {
        return false;
    }

    if (!ctx.is_auth_policy_session_loaded) {
        LOG_ERR("Must specify policy session containing NV Change Auth ");
        return false;
    }

    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx, 
                        ctx.tpm_handle_context_object.tr_handle, 
                        &ctx.auths.tpm_handle.old.auth,
                        ctx.auths.tpm_handle.old.session);
    if (shandle == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return false;
    }

    TSS2_RC rval = Esys_NV_ChangeAuth(ectx, 
                        ctx.tpm_handle_context_object.tr_handle,
                        shandle, ESYS_TR_NONE, ESYS_TR_NONE, &ctx.auths.tpm_handle.new.auth.hmac);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ChangeAuth, rval);
        return false;
    }

    return true;
}

static bool process_change_tpm_handle_auth(ESYS_CONTEXT *ectx) {

    bool result = process_tpm_handle_auths(ectx);
    if (!result) {
        return false;
    }

    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx,
                        ctx.tpm_handle_context_object.tr_handle,
                        &ctx.auths.tpm_handle.old.auth,
                        ctx.auths.tpm_handle.old.session);
    if (shandle == ESYS_TR_NONE) {
        return false;
    }

    TPM2B_PRIVATE *outPrivate = NULL;
    TSS2_RC rval = Esys_ObjectChangeAuth(ectx,
                        ctx.tpm_handle_context_object.tr_handle,
                        ctx.tpm_handle_parent_context_object.tr_handle,
                        shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                        &ctx.auths.tpm_handle.new.auth.hmac, &outPrivate);

    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ObjectChangeAuth, rval);
        return false;
    }

    if (ctx.flags.r) {
        bool res = files_save_private(outPrivate, ctx.opr_path);
        if (!res) {
            return false;
        }
    }

    free(outPrivate);

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {

    case 'o':
        ctx.flags.o = 1;
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
    case 'O':
        ctx.flags.O = 1;
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
    case 'a':
        ctx.flags.a = 1;
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
        { "new-owner-passwd",           required_argument, NULL, 'o' },
        { "current-owner-passwd",       required_argument, NULL, 'O' },
        { "new-endorsement-passwd",     required_argument, NULL, 'e' },
        { "current-endorsement-passwd", required_argument, NULL, 'E' },
        { "new-lockout-passwd",         required_argument, NULL, 'l' },
        { "current-lockout-passwd",     required_argument, NULL, 'L' },
        //Other TPM Handles: PERSISTENT/ TRANSIENT/ NV
        { "new-handle-passwd",          required_argument, NULL, 'p' },
        { "current-handle-passwd",      required_argument, NULL, 'P' },
        { "key-context",                required_argument, NULL, 'c' },
        //Additional parameters for PERSISTENT/ TRANSIENT Handles:
        { "key-parent-context",         required_argument, NULL, 'a' },
        { "privfile",                   required_argument, NULL, 'r' },
    };

    *opts = tpm2_options_new("o:e:l:O:E:L:p:P:c:a:r:S:", ARRAY_LEN(topts), topts,
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
                LOG_ERR("Unsupported handle type for auth change");
                return false;
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

    if ((ctx.is_persistent || ctx.is_transient) && (!ctx.flags.a || !ctx.flags.r)) {
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
        result = tpm2_util_object_load(ectx, ctx.tpm_handle_context_arg,
            &ctx.tpm_handle_context_object);
        if (!result) {
            LOG_ERR("Invalid TPM object handle");
            return -1;
        }
    }

    if (ctx.flags.a) {
        result = tpm2_util_object_load(ectx, ctx.tpm_handle_parent_context_arg,
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

    if (ctx.flags.o || ctx.flags.e || ctx.flags.l || ctx.flags.O || ctx.flags.E
            || ctx.flags.L) {
        result = process_change_hierarchy_auth(ectx);
    }

    /* true is success, coerce to 0 for program success */
    return result == false;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auths.endorse.old.session);
    tpm2_session_free(&ctx.auths.owner.old.session);
    tpm2_session_free(&ctx.auths.lockout.old.session);
    tpm2_session_free(&ctx.auths.tpm_handle.old.session);
}
