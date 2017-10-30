//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <sapi/tpm20.h>

#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "log.h"
#include "files.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_util.h"

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    UINT32 nv_index;
    UINT32 auth_handle;
    UINT16 data_size;
    UINT8 nv_buffer[MAX_NV_INDEX_SIZE];
    TPMS_AUTH_COMMAND session_data;
    char *input_file;
    UINT16 offset;
};

static tpm_nvwrite_ctx ctx = {
    .auth_handle = TPM_RH_PLATFORM,
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW),
};

static int nv_write(TSS2_SYS_CONTEXT *sapi_context) {

    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPM2B_MAX_NV_BUFFER nv_write_data;

    TPMS_AUTH_COMMAND *session_data_array[1] = { &ctx.session_data };
    TPMS_AUTH_RESPONSE *session_data_out_array[1] = { &session_data_out };

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    UINT16 data_offset = 0;

    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TPM_RC rval = tpm2_util_nv_read_public(sapi_context, ctx.nv_index, &nv_public);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Reading the public part of the nv index failed with: 0x%x", rval);
        return false;
    }

    if (ctx.offset + ctx.data_size > nv_public.t.nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.",
                ctx.offset, ctx.data_size, nv_public.t.nvPublic.dataSize);
        return false;
    }

    while (ctx.data_size > 0) {

        nv_write_data.t.size =
                ctx.data_size > MAX_NV_BUFFER_SIZE ?
                MAX_NV_BUFFER_SIZE : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.t.size);

        UINT16 i;
        for (i = 0; i < nv_write_data.t.size; i++) {
            nv_write_data.t.buffer[i] = ctx.nv_buffer[data_offset + i];
            tpm2_tool_output("%02x ", ctx.nv_buffer[data_offset + i]);
        }
        tpm2_tool_output("\n\n");

        rval = Tss2_Sys_NV_Write(sapi_context, ctx.auth_handle,
                ctx.nv_index, &sessions_data, &nv_write_data, ctx.offset + data_offset,
                &sessions_data_out);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_ERR(
                    "Failed to write NV area at index 0x%x (%d) offset 0x%x. Error:0x%x",
                    ctx.nv_index, ctx.nv_index, data_offset, rval);
            return false;
        }

        LOG_INFO("Success to write NV area at index 0x%x (%d) offset 0x%x.",
                ctx.nv_index, ctx.nv_index, data_offset);

        ctx.data_size -= nv_write_data.t.size;
        data_offset += nv_write_data.t.size;
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
        result = tpm2_util_string_to_uint32(value, &ctx.auth_handle);
        if (!result) {
            LOG_ERR("Could not convert auth handle to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.auth_handle == 0) {
            LOG_ERR("Auth handle cannot be 0");
            return false;
        }
        break;
    case 'f':
        ctx.input_file = value;
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!result) {
            LOG_ERR("Invalid handle password, got\"%s\"", value);
            return false;
        }
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.session_data.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
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

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index"       , required_argument, NULL, 'x' },
        { "auth-handle"  , required_argument, NULL, 'a' },
        { "file"        , required_argument, NULL, 'f' },
        { "handle-passwd", required_argument, NULL, 'P' },
        { "input-session-handle",1,          NULL, 'S' },
        { "offset"      , required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("x:a:f:P:S:o:", ARRAY_LEN(topts), topts, on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    ctx.data_size = MAX_NV_INDEX_SIZE;
    bool result = files_load_bytes_from_path(ctx.input_file, ctx.nv_buffer, &ctx.data_size);
    if (!result) {
        LOG_ERR("Failed to read data from %s", ctx.input_file);
        return -false;
    }

    return nv_write(sapi_context) != true;
}
