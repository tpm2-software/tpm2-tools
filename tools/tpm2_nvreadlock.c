/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvreadlock_ctx tpm_nvreadlock_ctx;
struct tpm_nvreadlock_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;
};

static tpm_nvreadlock_ctx ctx = {
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
    case 'a':
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

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
        ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    return tpm2_nvreadlock(ectx, &ctx.auth_hierarchy.object, ctx.nv_index);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
