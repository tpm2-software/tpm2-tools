/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"

typedef struct tpm_nvsetbits_ctx tpm_nvsetbits_ctx;
struct tpm_nvsetbits_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    const char *bit_string;
    TPM2_HANDLE nv_index;

    char *cp_hash_path;
};

static tpm_nvsetbits_ctx ctx;

static bool on_arg(int argc, char **argv) {
    /* If the user doesn't specify an authorization hierarchy use the index
     * passed to -x/--index for the authorization index.
     */
    if (!ctx.auth_hierarchy.ctx_path) {
        ctx.auth_hierarchy.ctx_path = argv[0];
    }
    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool on_option(char key, char *value) {

    switch (key) {

    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'i':
        ctx.bit_string = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "auth",      required_argument, NULL, 'P' },
        { "bits",      required_argument, NULL, 'i' },
        { "cphash",    required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:P:i:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.bit_string) {
        LOG_ERR("Expected option --bits for specifying the bits to set");
        return tool_rc_option_error;
    }

    UINT64 bits = 0;
    bool result = tpm2_util_string_to_uint64(ctx.bit_string, &bits);
    if (!result) {
        LOG_ERR("Could not convert option argument to number, got: \"%s\"",
                ctx.bit_string);
        return tool_rc_general_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    if (!ctx.cp_hash_path) {
        return tpm2_nvsetbits(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            bits, NULL);
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = tpm2_nvsetbits(ectx, &ctx.auth_hierarchy.object, ctx.nv_index, bits,
        &cp_hash);
    if (rc != tool_rc_success) {
        return rc;
    }

    result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    if (!ctx.cp_hash_path) {
        return tpm2_session_close(&ctx.auth_hierarchy.object.session);
    }
    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvsetbits", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
