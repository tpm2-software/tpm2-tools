/* SPDX-License-Identifier: BSD-3-Clause */

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

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;

    UINT8 nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    FILE *input_file;
    UINT16 data_size;
    UINT16 offset;
};

static tpm_nvwrite_ctx ctx;

static tool_rc nv_write(ESYS_CONTEXT *ectx) {

    TPM2B_MAX_NV_BUFFER nv_write_data;
    UINT16 data_offset = 0;

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
        return rc;
    }

    if (ctx.offset + ctx.data_size > nv_public->nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.",
                ctx.offset, ctx.data_size, nv_public->nvPublic.dataSize);
        free(nv_public);
        return tool_rc_general_error;
    }
    free(nv_public);

    UINT32 max_data_size;
    rc = tpm2_util_nv_max_buffer_size(ectx, &max_data_size);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (max_data_size > TPM2_MAX_NV_BUFFER_SIZE) {
        max_data_size = TPM2_MAX_NV_BUFFER_SIZE;
    }
    else if (max_data_size == 0) {
        max_data_size = NV_DEFAULT_BUFFER_SIZE;
    }

    while (ctx.data_size > 0) {

        nv_write_data.size =
                ctx.data_size > max_data_size ?
                        max_data_size : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.size);

        memcpy(nv_write_data.buffer, &ctx.nv_buffer[data_offset], nv_write_data.size);

        rc = tpm2_nvwrite(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
            &nv_write_data, ctx.offset + data_offset);
        if (rc != tool_rc_success) {
            return rc;
        }

        ctx.data_size -= nv_write_data.size;
        data_offset += nv_write_data.size;
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
        /*
         * If the users doesn't specify an authorization hierarchy use the index
         * passed to -x/--index for the authorization index.
         */
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'a':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 0:
        if (!tpm2_util_string_to_uint16(value, &ctx.offset)) {
            LOG_ERR("Could not convert starting offset, got: \"%s\"",
                    value);
            return false;
        }
        break;
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one input file, got: %d", argc);
        return false;
    }

    ctx.input_file = fopen(argv[0], "rb");
    if (!ctx.input_file) {
        LOG_ERR("Could not open input file \"%s\", error: %s",
                argv[0], strerror(errno));
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",                required_argument, NULL, 'x' },
        { "hierarchy",            required_argument, NULL, 'a' },
        { "auth-hierarchy",       required_argument, NULL, 'P' },
        { "offset",               required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("x:a:P:", ARRAY_LEN(topts), topts,
                             on_option, on_args, 0);

    ctx.input_file = stdin;

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
        ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
        TPM2_HANDLES_ALL);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    /* Suppress error reporting with NULL path */
    unsigned long file_size;
    bool result = files_get_file_size(ctx.input_file, &file_size, NULL);

    if (result) {

        if (file_size > TPM2_MAX_NV_BUFFER_SIZE) {
            LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE, got %lu expected %u", file_size,
                    TPM2_MAX_NV_BUFFER_SIZE);
            return tool_rc_general_error;
        }

        /*
         * We know the size upfront, read it. Note that the size was already
         * bounded by TPM2_MAX_NV_BUFFER_SIZE
         */
        ctx.data_size = (UINT16) file_size;
        result = files_read_bytes(ctx.input_file, ctx.nv_buffer, ctx.data_size);
        if (!result)  {
            LOG_ERR("could not read input file");
            return tool_rc_general_error;
        }
    } else {
        /* we don't know the file size, ie it's a stream, read till end */
        size_t bytes = fread(ctx.nv_buffer, 1, TPM2_MAX_NV_BUFFER_SIZE, ctx.input_file);
        if (bytes != TPM2_MAX_NV_BUFFER_SIZE) {
            if (ferror(ctx.input_file)) {
                LOG_ERR("reading from input file failed: %s", strerror(errno));
                return tool_rc_general_error;
            }

            if (!feof(ctx.input_file)) {
                LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE: %u",
                        TPM2_MAX_NV_BUFFER_SIZE);
                return tool_rc_general_error;
            }
        }

        ctx.data_size = (UINT16)bytes;
    }

    return nv_write(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
