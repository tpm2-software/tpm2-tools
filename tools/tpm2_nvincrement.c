/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_nv_util.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvincrement_ctx tpm_nvincrement_ctx;
struct tpm_nvincrement_ctx {

    TPM2_HANDLE nv_index;
    TPMI_RH_PROVISION hierarchy;

    struct {
        char *auth_str;
        tpm2_session *session;
    } auth;

    struct {
        UINT8 a : 1;
    } flags;
};

static tpm_nvincrement_ctx ctx = {
    .hierarchy = TPM2_RH_OWNER
};

static bool nv_increment(ESYS_CONTEXT *ectx) {
    // Convert TPM2_HANDLE ctx.nv_index to an ESYS_TR
    ESYS_TR nv_index;
    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, ctx.nv_index,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv_index);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return false;
    }

    // Convert TPMI_RH_PROVISION ctx.auth.hierarchy to an ESYS_TR
    ESYS_TR hierarchy;
    if (ctx.hierarchy == ctx.nv_index) {
        hierarchy = nv_index;
    } else {
        hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(ctx.hierarchy);
    }

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, hierarchy,
                            ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return false;
    }

    rval = Esys_NV_Increment(ectx, hierarchy, nv_index,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to increment NV counter at index 0x%X", ctx.nv_index);
        LOG_PERR(Tss2_Sys_NV_Write, rval);
        return false;
    }

    return true;
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
        ctx.flags.a = 1;
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

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    /* If the users doesn't specify an authorisation hierarchy use the index
     * passed to -x/--index for the authorisation index.
     */
    if (!ctx.flags.a) {
        ctx.hierarchy = ctx.nv_index;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (!result) {
        LOG_ERR("Invalid handle authorization, got \"%s\"",
            ctx.auth.auth_str);
        goto out;
    }

    result = nv_increment(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    result = tpm2_session_close(&ctx.auth.session);
    if (!result) {
        rc = 1;
    }

    return rc;
}
