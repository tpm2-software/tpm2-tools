/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvreadlock_ctx tpm_nvreadlock_ctx;
struct tpm_nvreadlock_ctx {
    TPM2_HANDLE nv_index;
    TPMI_RH_PROVISION hierarchy;

    UINT32 size_to_read;
    UINT32 offset;

    struct {
        char *auth_str;
        tpm2_session *session;
    } auth;
};

static tpm_nvreadlock_ctx ctx = {
    .hierarchy = TPM2_RH_OWNER
};

static tool_rc nv_readlock(ESYS_CONTEXT *ectx) {

    ESYS_TR nv_handle;
    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, ctx.nv_index,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &nv_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return tool_rc_from_tpm(rval);
    }

    ESYS_TR hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(ctx.hierarchy);
    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, hierarchy,
                            ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return tool_rc_general_error;
    }

    rval = Esys_NV_ReadLock(ectx, hierarchy, nv_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to lock NVRAM area at index 0x%X" , ctx.nv_index);
        LOG_PERR(Esys_NV_ReadLock, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'x':
        result = tpm2_util_string_to_uint32(value, &ctx.nv_index);
        if (!result) {
            LOG_ERR("Could not convert NV index to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.nv_index == 0) {
            LOG_ERR("NV Index cannot be 0");
            return false;
        }
        break;
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            return false;
        }
        break;
    case 'P':
        ctx.auth.auth_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",                required_argument, NULL, 'x' },
        { "hierarchy",            required_argument, NULL, 'a' },
        { "auth-hierarchy",       required_argument, NULL, 'P' },
    };

    *opts = tpm2_options_new("x:a:P:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization, got \"%s\"",
            ctx.auth.auth_str);
       return rc;
    }

    return nv_readlock(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth.session);
}
