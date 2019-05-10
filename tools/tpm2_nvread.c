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
    TPM2_HANDLE nv_index;
    TPMI_RH_PROVISION hierarchy;

    UINT32 size_to_read;
    UINT32 offset;
    struct {
        char *auth_str;
        tpm2_session *session;
    } auth;
    char *output_file;
    struct {
        UINT8 a : 1;
    } flags;
};

static tpm_nvread_ctx ctx = {
    .hierarchy = TPM2_RH_OWNER
};

static bool nv_read(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UINT8* data_buffer = NULL;
    UINT16 bytes_written;
    bool result = tpm2_util_nv_read(ectx, ctx.nv_index, ctx.size_to_read,
                    ctx.offset, ctx.hierarchy, ctx.auth.session,
                    &data_buffer, &bytes_written);
    if (!result) {
        goto out;
    }

    /* dump data_buffer to output file, if specified */
    if (ctx.output_file) {
        if (!files_save_bytes_to_file(ctx.output_file, data_buffer, bytes_written)) {
            result = false;
            goto out;
        }
    /* else use stdout if quiet is not specified */
    } else if (!flags.quiet) {
        if (!files_write_bytes(stdout, data_buffer, bytes_written)) {
            result = false;
            goto out;
        }
    }

    result = true;

out:
    if (data_buffer) {
        free(data_buffer);
    }

    return result;
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
        break;
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            return false;
        }
        ctx.flags.a = 1;
        break;
    case 'o':
        ctx.output_file = value;
        break;
    case 'P':
        ctx.auth.auth_str = value;
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

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    /* If the users doesn't specify an authorisation hierarchy use the index
     * passed to -x/--index for the authorisation index.
     */
    if (!ctx.flags.a) {
        ctx.hierarchy = ctx.nv_index;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (!result) {
        LOG_ERR("Invalid handle authorization, got \"%s\"",
            ctx.auth.auth_str);
        return false;
    }

    result = nv_read(ectx, flags);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    result = tpm2_session_close(&ctx.auth.session);
    if (!result) {
        rc = 1;
    }

    return rc;
}
