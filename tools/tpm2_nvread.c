/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;
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
    UINT32 size_to_read;
    UINT32 offset;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
        TPMI_RH_PROVISION hierarchy;
    } auth;
    char *output_file;
    char *raw_pcrs_file;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 L : 1;
        UINT8 P : 1;
        UINT8 a : 1;
    } flags;
    char *hierarchy_auth_str;
};

static tpm_nvread_ctx ctx = {
    .auth = {
        .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .hierarchy = TPM2_RH_OWNER
    }
};

static bool nv_read(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UINT8* data_buffer = NULL;
    UINT16 bytes_written;
    bool result = tpm2_util_nv_read(ectx, ctx.nv_index, ctx.size_to_read,
                    ctx.offset, ctx.auth.hierarchy, &ctx.auth.session_data, ctx.auth.session,
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
        result = tpm2_hierarchy_from_optarg(value, &ctx.auth.hierarchy,
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
        ctx.flags.P = 1;
        ctx.hierarchy_auth_str = value;
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
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
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
        { "set-list",             required_argument, NULL, 'L' },
        { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("x:a:s:o:P:L:F:", ARRAY_LEN(topts),
                             topts, on_option, NULL, 0);

    return *opts != NULL;
}

static bool start_auth_session(ESYS_CONTEXT *ectx) {

    tpm2_session_data *session_data =
            tpm2_session_data_new(TPM2_SE_POLICY);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    ctx.auth.session = tpm2_session_new(ectx,
            session_data);
    if (!ctx.auth.session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    bool result = tpm2_policy_build_pcr(ectx, ctx.auth.session,
            ctx.raw_pcrs_file,
            &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build a pcr policy");
        return false;
    }

    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    if (ctx.flags.L && ctx.auth.session) {
        LOG_ERR("Can only use either existing session or a new session,"
                " not both!");
        goto out;
    }

    if (ctx.flags.L) {
        result = start_auth_session(ectx);
        if (!result) {
            goto out;
        }
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.hierarchy_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid handle authorization, got \"%s\"",
                ctx.hierarchy_auth_str);
            return false;
        }
    }

    /* If the users doesn't specify an authorisation hierarchy use the index
     * passed to -x/--index for the authorisation index.
     */
    if (!ctx.flags.a) {
        ctx.auth.hierarchy = ctx.nv_index;
    }

    result = nv_read(ectx, flags);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    if (ctx.flags.L) {
        ESYS_TR sess = tpm2_session_get_handle(ctx.auth.session);
        TSS2_RC rval = Esys_FlushContext(ectx, sess);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_FlushContext, rval);
            rc = 1;
        }
    } else {
        result = tpm2_session_save(ectx, ctx.auth.session, NULL);
        if (!result) {
            rc = 1;
        }
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
