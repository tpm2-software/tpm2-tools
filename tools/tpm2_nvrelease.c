/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2.h"
#include "tpm2_options.h"

typedef struct tpm_nvrelease_ctx tpm_nvrelease_ctx;
struct tpm_nvrelease_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;
};

static tpm_nvrelease_ctx ctx = {
    .auth_hierarchy.ctx_path = "owner",
};

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
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",          required_argument, NULL, 'x' },
        { "hierarchy",      required_argument, NULL, 'C' },
        { "auth",           required_argument, NULL, 'P' },
    };

    *opts = tpm2_options_new("x:C:P:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
        ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
        TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    return tpm2_nvrelease(ectx, &ctx.auth_hierarchy.object, ctx.nv_index);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
