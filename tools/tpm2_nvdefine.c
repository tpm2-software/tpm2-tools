/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvdefine_ctx tpm_nvdefine_ctx;
struct tpm_nvdefine_ctx {
    UINT32 nvIndex;
    UINT16 size;
    TPMA_NV nvAttribute;
    TPM2B_AUTH nvAuth;
    struct {
        TPMI_RH_PROVISION handle;
        char *auth_str;
        tpm2_session *session;
    } hierarchy;
    char *policy_file;
    char *index_auth_str;
};

static tpm_nvdefine_ctx ctx = {
    .hierarchy = {
        .handle = TPM2_RH_OWNER
    },
    .nvAuth = TPM2B_EMPTY_INIT,
    .size = TPM2_MAX_NV_BUFFER_SIZE,
};

static int nv_space_define(ESYS_CONTEXT *ectx) {

    TPM2B_NV_PUBLIC public_info = TPM2B_EMPTY_INIT;

    public_info.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    public_info.nvPublic.nvIndex = ctx.nvIndex;
    public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;

    // Now set the attributes.
    public_info.nvPublic.attributes = ctx.nvAttribute;

    if (!ctx.size) {
        LOG_WARN("Defining an index with size 0");
    }

    if (ctx.policy_file) {
        public_info.nvPublic.authPolicy.size  = BUFFER_SIZE(TPM2B_DIGEST, buffer);
        if(!files_load_bytes_from_path(ctx.policy_file, public_info.nvPublic.authPolicy.buffer, &public_info.nvPublic.authPolicy.size )) {
            return false;
        }
    } 

    public_info.nvPublic.dataSize = ctx.size;

    ESYS_TR nvHandle;
    ESYS_TR auth_handle = tpm2_tpmi_hierarchy_to_esys_tr(ctx.hierarchy.handle);
    ESYS_TR shandle1;
    TSS2_RC rval;

    shandle1 = tpm2_auth_util_get_shandle(ectx, auth_handle,
                    ctx.hierarchy.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return false;
    }

    rval = Esys_NV_DefineSpace(ectx, auth_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &ctx.nvAuth, &public_info, &nvHandle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to define NV area at index 0x%X", ctx.nvIndex);
        LOG_PERR(Esys_NV_DefineSpace, rval);
        return false;
    }

    LOG_INFO("Success to define NV area at index 0x%x (%d).", ctx.nvIndex, nvHandle);

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'x':
        result = tpm2_util_string_to_uint32(value, &ctx.nvIndex);
        if (!result) {
            LOG_ERR("Could not convert NV index to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.nvIndex == 0) {
                LOG_ERR("NV Index cannot be 0");
                return false;
        }
        break;
        case 'a':
            result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy.handle,
                    TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
            if (!result) {
                LOG_ERR("get h failed");
                return false;
            }
        break;
        case 'P':
            ctx.hierarchy.auth_str = value;
        break;
        case 's':
            result = tpm2_util_string_to_uint16(value, &ctx.size);
            if (!result) {
                LOG_ERR("Could not convert size to number, got: \"%s\"",
                        value);
                return false;
            }
            break;
        case 'b':
            result = tpm2_util_string_to_uint32(value, &ctx.nvAttribute);
            if (!result) {
                result = tpm2_attr_util_nv_strtoattr(value, &ctx.nvAttribute);
                if (!result) {
                    LOG_ERR("Could not convert NV attribute to number or keyword, got: \"%s\"",
                            value);
                    return false;
                }
            }
            break;
        case 'p':
            ctx.index_auth_str = value;
            break;
        case 'L':
            ctx.policy_file = value;
            break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",                  required_argument,  NULL,   'x' },
        { "hierarchy",              required_argument,  NULL,   'a' },
        { "size",                   required_argument,  NULL,   's' },
        { "attributes",             required_argument,  NULL,   'b' },
        { "auth-hierarchy",         required_argument,  NULL,   'P' },
        { "auth-index",             required_argument,  NULL,   'p' },
        { "policy-file",            required_argument,  NULL,   'L' },
    };

    *opts = tpm2_options_new("x:a:s:b:P:p:L:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result;
    int rc = 1;

    result = tpm2_auth_util_from_optarg(ectx, ctx.hierarchy.auth_str,
            &ctx.hierarchy.session, false);
    if (!result) {
        LOG_ERR("Invalid handle authorization, got \"%s\"", ctx.hierarchy.auth_str);
        goto out;
    }

    tpm2_session *tmp;
    result = tpm2_auth_util_from_optarg(NULL, ctx.index_auth_str,
            &tmp, true);
    if (!result) {
        LOG_ERR("Invalid index authorization, got\"%s\"", ctx.index_auth_str);
        goto out;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.nvAuth = *auth;

    tpm2_session_close(&tmp);

    result = nv_space_define(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    result = tpm2_session_close(&ctx.hierarchy.session);
    if (!result) {
        rc = 1;
    }

    return rc;
}
