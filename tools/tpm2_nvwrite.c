/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;

    BYTE nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    FILE *input_file;
    UINT16 data_size;
    UINT16 offset;
    char *cp_hash_path;
};

static tpm_nvwrite_ctx ctx = {
    .data_size = TPM2_MAX_NV_BUFFER_SIZE
};

static bool is_input_options_args_valid(ESYS_CONTEXT *ectx) {

    if (ctx.cp_hash_path && ctx.data_size > TPM2_MAX_NV_BUFFER_SIZE) {
        LOG_ERR("Cannot calculat cpHash for buffers larger than NV max buffer");
        return false;
    }

    if (!ctx.data_size) {
        LOG_WARN("Data to write is of size 0");
    }

    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC *nv_public = NULL;
    tool_rc rc = tpm2_util_nv_read_public(ectx, ctx.nv_index, &nv_public);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to write NVRAM public area at index 0x%X",
                ctx.nv_index);
        free(nv_public);
        return false;
    }

    if (ctx.offset + ctx.data_size > nv_public->nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.", ctx.offset, ctx.data_size,
                nv_public->nvPublic.dataSize);
        free(nv_public);
        return false;
    }
    free(nv_public);
    return true;
}

static tool_rc nv_write(ESYS_CONTEXT *ectx) {

    TPM2B_MAX_NV_BUFFER nv_write_data;
    UINT16 data_offset = 0;

    if (ctx.cp_hash_path) {
        nv_write_data.size = ctx.data_size;
        memcpy(nv_write_data.buffer, &ctx.nv_buffer, ctx.data_size);
        LOG_WARN("Calculating cpHash. Exiting without performing write.");
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_nvwrite(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
                &nv_write_data, ctx.offset, &cp_hash);
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

    UINT32 max_data_size;
    tool_rc rc = tpm2_util_nv_max_buffer_size(ectx, &max_data_size);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (max_data_size > TPM2_MAX_NV_BUFFER_SIZE) {
        max_data_size = TPM2_MAX_NV_BUFFER_SIZE;
    } else if (max_data_size == 0) {
        max_data_size = NV_DEFAULT_BUFFER_SIZE;
    }

    while (ctx.data_size > 0) {

        nv_write_data.size =
                ctx.data_size > max_data_size ? max_data_size : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.size);

        memcpy(nv_write_data.buffer, &ctx.nv_buffer[data_offset],
                nv_write_data.size);

        rc = tpm2_nvwrite(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
                &nv_write_data, ctx.offset + data_offset, NULL);
        if (rc != tool_rc_success) {
            return rc;
        }

        ctx.data_size -= nv_write_data.size;
        data_offset += nv_write_data.size;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {
    char *input_file;
    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'i':
        input_file = strcmp("-", value) ? value : NULL;
        return files_load_bytes_from_buffer_or_file_or_stdin(NULL, input_file,
                &ctx.data_size, ctx.nv_buffer);
        break;
    case 0:
        if (!tpm2_util_string_to_uint16(value, &ctx.offset)) {
            LOG_ERR("Could not convert starting offset, got: \"%s\"", value);
            return false;
        }
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
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

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",            required_argument, NULL, 'C' },
        { "auth",                 required_argument, NULL, 'P' },
        { "input",                required_argument, NULL, 'i' },
        { "offset",               required_argument, NULL,  0  },
        { "cphash",               required_argument, NULL,  1  },
    };

    *opts = tpm2_options_new("C:P:i:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_options_args_valid(ectx);
    if (!retval) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    return nv_write(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvwrite", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
