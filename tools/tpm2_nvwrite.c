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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm_session.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    UINT32 nv_index;
    UINT32 auth_handle;
    UINT16 data_size;
    UINT8 nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    TPMS_AUTH_COMMAND session_data;
    FILE *input_file;
    UINT16 offset;
    char *raw_pcrs_file;
    SESSION *policy_session;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 L : 1;
    } flags;
};

static tpm_nvwrite_ctx ctx = {
    .auth_handle = TPM2_RH_PLATFORM,
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
};

static bool nv_write(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_MAX_NV_BUFFER nv_write_data;

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TSS2L_SYS_AUTH_COMMAND sessions_data = { 1, { ctx.session_data }};

    UINT16 data_offset = 0;

    if (!ctx.data_size) {
        LOG_WARN("Data to write is of size 0");
    }

    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TSS2_RC rval = tpm2_util_nv_read_public(sapi_context, ctx.nv_index, &nv_public);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Reading the public part of the nv index failed with: 0x%x", rval);
        return false;
    }

    if (ctx.offset + ctx.data_size > nv_public.nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.",
                ctx.offset, ctx.data_size, nv_public.nvPublic.dataSize);
        return false;
    }

    UINT32 max_data_size;
    rval = tpm2_util_nv_max_buffer_size(sapi_context, &max_data_size);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    if (max_data_size > TPM2_MAX_NV_BUFFER_SIZE) {
        max_data_size = TPM2_MAX_NV_BUFFER_SIZE;
    }

    while (ctx.data_size > 0) {

        nv_write_data.size =
                ctx.data_size > max_data_size ?
                        max_data_size : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.size);

        memcpy(nv_write_data.buffer, &ctx.nv_buffer[data_offset], nv_write_data.size);

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_NV_Write(sapi_context, ctx.auth_handle,
                ctx.nv_index, &sessions_data, &nv_write_data, ctx.offset + data_offset,
                &sessions_data_out));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR(
                    "Failed to write NV area at index 0x%x (%d) offset 0x%x. Error:0x%x",
                    ctx.nv_index, ctx.nv_index, data_offset, rval);
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
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = optarg;
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
        { "auth-handle",          required_argument, NULL, 'a' },
        { "handle-passwd",        required_argument, NULL, 'P' },
        { "input-session-handle", required_argument, NULL, 'S' },
        { "offset",               required_argument, NULL, 'o' },
        { "set-list",             required_argument, NULL, 'L' },
        { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("x:a:P:S:o:L:F:", ARRAY_LEN(topts), topts,
            on_option, on_args);

    ctx.input_file = stdin;

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;

    /* set up PCR policy if specified */
    if (ctx.flags.L) {
        TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

        TSS2_RC rval = tpm2_policy_build(sapi_context, &ctx.policy_session,
                                        TPM2_SE_POLICY, TPM2_ALG_SHA256, ctx.pcr_selection,
                                        ctx.raw_pcrs_file, &pcr_digest, true,
                                        tpm2_policy_pcr_build);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Building PCR policy failed: 0x%x", rval);
            return 1;
        }
        ctx.session_data.sessionHandle = ctx.policy_session->sessionHandle;
        ctx.session_data.sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    }

    /* Suppress error reporting with NULL path */
    unsigned long file_size;
    bool res = files_get_file_size(ctx.input_file, &file_size, NULL);

    if (res && file_size > TPM2_MAX_NV_BUFFER_SIZE) {
        LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE, got %lu expected %u", file_size,
                TPM2_MAX_NV_BUFFER_SIZE);
        goto out;
    }

    if (res) {
        /*
         * We know the size upfront, read it. Note that the size was already
         * bounded by TPM2_MAX_NV_BUFFER_SIZE
         */
        ctx.data_size = (UINT16) file_size;
        res = files_read_bytes(ctx.input_file, ctx.nv_buffer, ctx.data_size);
        if (!res)  {
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

    res = nv_write(sapi_context);
    if (!res) {
        goto out;
    }

    rc = 0;

out:
    if (ctx.input_file) {
        fclose(ctx.input_file);
    }

    if (ctx.policy_session) {
        TSS2_RC rval = Tss2_Sys_FlushContext(sapi_context,
                                            ctx.policy_session->sessionHandle);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context: 0x%x", rval);
            return 1;
        }

        tpm_session_auth_end(ctx.policy_session);
    }

    return rc;
}
