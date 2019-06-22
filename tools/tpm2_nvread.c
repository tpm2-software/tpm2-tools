/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

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
};

static tpm_nvread_ctx ctx;

static tool_rc nv_read(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UINT8* data_buffer = NULL;
    UINT16 bytes_written;
    tool_rc rc = tpm2_util_nv_read(ectx, ctx.nv_index, ctx.size_to_read,
                    ctx.offset, ctx.auth_hierarchy.object.handle,
                    ctx.auth_hierarchy.object.session, &data_buffer,
                    &bytes_written);
    if (rc != tool_rc_success) {
        goto out;
    }

    /* dump data_buffer to output file, if specified */
    if (ctx.output_file) {
        if (!files_save_bytes_to_file(ctx.output_file, data_buffer, bytes_written)) {
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
    case 'o':
        ctx.output_file = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 's':
        result = tpm2_util_string_to_uint32(value, &ctx.size_to_read);
        if (!result) {
            LOG_ERR("Could not convert size to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 0:
        result = tpm2_util_string_to_uint32(value, &ctx.offset);
        if (!result) {
            LOG_ERR("Could not convert offset to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
        /* no default */
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",                required_argument, NULL, 'x' },
        { "hierarchy",            required_argument, NULL, 'a' },
        { "out-file",             required_argument, NULL, 'o' },
        { "size",                 required_argument, NULL, 's' },
        { "offset",               required_argument, NULL,  0  },
        { "auth-hierarchy",       required_argument, NULL, 'P' },
    };

    *opts = tpm2_options_new("x:a:s:o:P:", ARRAY_LEN(topts),
                             topts, on_option, NULL, 0);

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

    return nv_read(ectx, flags);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}
