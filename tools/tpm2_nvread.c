/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"

typedef struct tpm_nvread_ctx tpm_nvread_ctx;
struct tpm_nvread_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;

    UINT32 size_to_read;
    UINT32 offset;
    char *output_file;

    char *cp_hash_path;
};

static tpm_nvread_ctx ctx;

static tool_rc nv_read(ESYS_CONTEXT *ectx, tpm2_option_flags flags,
    TPM2B_DIGEST *cp_hash) {

    UINT8* data_buffer = NULL;
    UINT16 bytes_written = 0;
    tool_rc rc = tpm2_util_nv_read(ectx, ctx.nv_index, ctx.size_to_read,
            ctx.offset, &ctx.auth_hierarchy.object, &data_buffer, &bytes_written,
            cp_hash);
    if (rc != tool_rc_success || cp_hash != NULL) {
        goto out;
    }

    /* dump data_buffer to output file, if specified */
    if (ctx.output_file) {
        if (!files_save_bytes_to_file(ctx.output_file, data_buffer,
                bytes_written)) {
            rc = tool_rc_general_error;
            goto out;
        }
        /* else use stdout if quiet is not specified */
    } else if (!flags.quiet) {
        if (!files_write_bytes(stdout, data_buffer, bytes_written)) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

out:
    if (data_buffer) {
        free(data_buffer);
    }

    return rc;
}

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

    bool result;

    switch (key) {

    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'o':
        ctx.output_file = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 's':
        result = tpm2_util_string_to_uint32(value, &ctx.size_to_read);
        if (!result) {
            LOG_ERR("Could not convert size to number, got: \"%s\"", value);
            return false;
        }
        break;
    case 0:
        result = tpm2_util_string_to_uint32(value, &ctx.offset);
        if (!result) {
            LOG_ERR("Could not convert offset to number, got: \"%s\"", value);
            return false;
        }
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
        /* no default */
    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "output",    required_argument, NULL, 'o' },
        { "size",      required_argument, NULL, 's' },
        { "offset",    required_argument, NULL,  0  },
        { "cphash",    required_argument, NULL,  1  },
        { "auth",      required_argument, NULL, 'P' },
    };

    *opts = tpm2_options_new("C:s:o:P:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    if (!ctx.cp_hash_path) {
        return nv_read(ectx, flags, NULL);
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = nv_read(ectx, flags, &cp_hash);
    if (rc != tool_rc_success) {
        LOG_ERR("CpHash calculation failed!");
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
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvread", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
