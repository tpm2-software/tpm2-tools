/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct tpm_load_ctx tpm_load_ctx;
struct tpm_load_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        const char *pubpath;
        TPM2B_PUBLIC public;
        const char *privpath;
        TPM2B_PRIVATE private;
        ESYS_TR handle;
    } object;

    const char *namepath;
    const char *contextpath;
    char *cp_hash_path;
};

static tpm_load_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'u':
        ctx.object.pubpath = value;
        break;
    case 'r':
        ctx.object.privpath = value;
        break;
    case 'n':
        ctx.namepath = value;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'c':
        ctx.contextpath = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth",           required_argument, NULL, 'P' },
      { "public",         required_argument, NULL, 'u' },
      { "private",        required_argument, NULL, 'r' },
      { "name",           required_argument, NULL, 'n' },
      { "key-context",    required_argument, NULL, 'c' },
      { "parent-context", required_argument, NULL, 'C' },
      { "cphash",         required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("P:u:r:n:C:c:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc check_opts(void) {

    tool_rc rc = tool_rc_success;
    if (!ctx.parent.ctx_path) {
        LOG_ERR("Expected parent object via -C");
        rc = tool_rc_option_error;
    }

    if (!ctx.object.pubpath) {
        LOG_ERR("Expected public object portion via -u");
        rc = tool_rc_option_error;
    }

    if (!ctx.object.privpath) {
        LOG_ERR("Expected public object portion via -r");
        rc = tool_rc_option_error;
    }

    if (!ctx.contextpath && !ctx.cp_hash_path) {
        LOG_ERR("Expected option -c");
        rc = tool_rc_option_error;
    }

    if (ctx.contextpath && ctx.cp_hash_path) {
        LOG_ERR("Cannot output contextpath when calculating cp_hash");
        rc = tool_rc_option_error;
    }

    return rc;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    bool res = files_load_public(ctx.object.pubpath, &ctx.object.public);
    if (!res) {
        return tool_rc_general_error;
    }

    res = files_load_private(ctx.object.privpath, &ctx.object.private);
    if (!res) {
        return tool_rc_general_error;
    }

    return tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false,
            TPM2_HANDLE_ALL_W_NV);
}

static tool_rc finish(ESYS_CONTEXT *ectx) {

    TPM2B_NAME *name;
    tool_rc rc = tpm2_tr_get_name(ectx, ctx.object.handle, &name);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.namepath) {
        bool result = files_save_bytes_to_file(ctx.namepath, name->name,
                name->size);
        free(name);
        if (!result) {
            return tool_rc_general_error;
        }
    } else {
        tpm2_tool_output("name: ");
        tpm2_util_print_tpm2b(name);
        tpm2_tool_output("\n");
        free(name);
    }

    return files_save_tpm_context_to_path(ectx, ctx.object.handle,
            ctx.contextpath);
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = check_opts();
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (!ctx.cp_hash_path) {
        rc = tpm2_load(ectx, &ctx.parent.object, &ctx.object.private,
            &ctx.object.public, &ctx.object.handle, NULL);
        if (rc != tool_rc_success) {
            return rc;
        }

        return finish(ectx);
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = tpm2_load(ectx, &ctx.parent.object, &ctx.object.private,
            &ctx.object.public, &ctx.object.handle, &cp_hash);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.parent.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("load", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
