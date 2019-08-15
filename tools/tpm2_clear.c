/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

typedef struct clear_ctx clear_ctx;
struct clear_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

};

static clear_ctx ctx = {
    .auth_hierarchy.ctx_path = "l",
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    }

    return true;
}

bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify a single auth value");
        return false;
    }

    if (!argc) {
        //empty auth
        return true;
    }

    ctx.auth_hierarchy.auth_str = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-hierarchy",     no_argument,       NULL, 'c' },
    };

    *opts = tpm2_options_new("c:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, true,
            TPM2_HANDLE_FLAGS_L | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid lockout authorization");
        return rc;
    }

    return tpm2_clear(ectx, &ctx.auth_hierarchy.object);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
