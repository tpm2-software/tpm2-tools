//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>

#include <tss2/tss2_sys.h>

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

typedef struct hmac_update_cb_data hmac_update_cb_data;
struct hmac_update_cb_data {
    UINT16 offset;
    TPM2B_MAX_NV_BUFFER *nv_write_data;
};

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    UINT32 nv_index;
    UINT16 data_size;
    UINT8 nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    struct {
        tpm2_auth authorizations;
        TPMI_RH_PROVISION hierarchy;
    } auth;
    FILE *input_file;
    UINT16 offset;
};

static tpm_nvwrite_ctx ctx = {
    .auth = {
        .hierarchy = TPM2_RH_OWNER,
        .authorizations = TPM2_AUTH_INIT
    }
};

static bool nv_write(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_MAX_NV_BUFFER nv_write_data;

    UINT16 data_offset = 0;

    if (!ctx.data_size) {
        LOG_WARN("Data to write is of size 0");
    }

    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    bool res = tpm2_util_nv_read_public(sapi_context, ctx.nv_index, &nv_public);
    if (!res) {
        LOG_ERR("Failed to write NVRAM public area at index 0x%X",
                ctx.nv_index);
        return false;
    }

    if (ctx.offset + ctx.data_size > nv_public.nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.",
                ctx.offset, ctx.data_size, nv_public.nvPublic.dataSize);
        return false;
    }

    UINT32 max_data_size;
    res = tpm2_util_nv_max_buffer_size(sapi_context, &max_data_size);
    if (!res) {
        return false;
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

        hmac_update_cb_data udata = {
            .offset = data_offset,
            .nv_write_data = &nv_write_data
        };

        res = tpm2b_auth_update(sapi_context, &ctx.auth.authorizations, &udata);
        if (!res) {
            LOG_ERR("Error updating authentications");
        }

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_NV_Write(sapi_context,
                ctx.auth.hierarchy, ctx.nv_index, &ctx.auth.authorizations.auth_list, &nv_write_data,
                ctx.offset + data_offset, &ctx.auth.authorizations.resp_list));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed to write NV area at index 0x%X", ctx.nv_index);
            LOG_PERR(Tss2_Sys_NV_Write, rval);
            return false;
        }

        LOG_INFO("Success to write NV area at index 0x%x (%d) offset 0x%x.",
                ctx.nv_index, ctx.nv_index, data_offset);

        ctx.data_size -= nv_write_data.size;
        data_offset += nv_write_data.size;
    }

    return true;
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
        break;
    case 'P':
        result = tpm2_auth_util_set_opt(value, &ctx.auth.authorizations);
        if (!result) {
            LOG_ERR("Invalid handle authorization, got\"%s\"", value);
            return false;
        }
        break;
    case 'o':
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
        { "hierarchy",       required_argument, NULL, 'a' },
        { "auth-hierarchy", required_argument, NULL, 'P' },
        { "offset",               required_argument, NULL, 'o' },
        { "set-list",             required_argument, NULL, 'L' },
        { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("x:a:P:o:L:F:", ARRAY_LEN(topts), topts,
                             on_option, on_args, 0);

    ctx.input_file = stdin;

    return *opts != NULL;
}

static bool hmac_update_cb(TSS2_SYS_CONTEXT *sapi_context, void *userdata) {

    hmac_update_cb_data *udata = (hmac_update_cb_data *)userdata;

    TSS2_RC rval = TSS2_RETRY_EXP( Tss2_Sys_NV_Write_Prepare(sapi_context,
                                ctx.auth.hierarchy, ctx.nv_index, udata->nv_write_data,
                                ctx.offset + udata->offset));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_NV_Write_Prepare, rval);
        return false;
    }

    return true;
}

static bool hmac_init_cb(tpm2_session_data *d) {

    TPM2_HANDLE handles[2] = {
            ctx.auth.hierarchy,
            ctx.nv_index
    };

    tpm2_session_set_auth_handles(d, handles);

    return true;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;

    tpm2_auth_cb auth_cb = {
        .hmac = {
            .init = hmac_init_cb,
            .update = hmac_update_cb
        }
    };

    bool result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auth.authorizations, &auth_cb,
            true);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms");
        goto out;
    }

    /* Suppress error reporting with NULL path */
    unsigned long file_size;
    result = files_get_file_size(ctx.input_file, &file_size, NULL);

    if (result && file_size > TPM2_MAX_NV_BUFFER_SIZE) {
        LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE, got %lu expected %u", file_size,
                TPM2_MAX_NV_BUFFER_SIZE);
        goto out;
    }

    if (result) {
        /*
         * We know the size upfront, read it. Note that the size was already
         * bounded by TPM2_MAX_NV_BUFFER_SIZE
         */
        ctx.data_size = (UINT16) file_size;
        result = files_read_bytes(ctx.input_file, ctx.nv_buffer, ctx.data_size);
        if (!result)  {
            LOG_ERR("could not read input file");
            goto out;
        }
    } else {
        /* we don't know the file size, ie it's a stream, read till end */
        size_t bytes = fread(ctx.nv_buffer, 1, TPM2_MAX_NV_BUFFER_SIZE, ctx.input_file);
        if (bytes != TPM2_MAX_NV_BUFFER_SIZE) {
            if (ferror(ctx.input_file)) {
                LOG_ERR("reading from input file failed: %s", strerror(errno));
                goto out;
            }

            if (!feof(ctx.input_file)) {
                LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE: %u",
                        TPM2_MAX_NV_BUFFER_SIZE);
                goto out;
            }
        }

        ctx.data_size = (UINT16)bytes;
    }

    result = nv_write(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_auth_util_free(sapi_context, &ctx.auth.authorizations);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
    }

    return result ? rc : 1;
}
