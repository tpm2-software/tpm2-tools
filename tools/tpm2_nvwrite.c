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
#include "tpm2_hmac_auth.h"
#include "tpm2_nv_util.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    UINT32 nv_index;
    UINT16 data_size;
    UINT8 nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    FILE *input_file;
    UINT16 offset;
    char *raw_pcrs_file;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 L : 1;
    } flags;
    struct {
        bool is_hmac_auth; //Required since TPM2_SE_HMAC is same as session type
                           //when creating new session object
        tpm2_session_data *session_data[MAX_AUTH_SESSIONS];
        tpm2_session *session[MAX_AUTH_SESSIONS];
        TPMI_RH_PROVISION hierarchy;
        TSS2L_SYS_AUTH_COMMAND auth_list;
    } auth;
};

static tpm_nvwrite_ctx ctx = {
    .auth = {
        .is_hmac_auth = false,
        .hierarchy = TPM2_RH_OWNER,
    },
};

static bool nv_write(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_MAX_NV_BUFFER nv_write_data;

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    UINT16 data_offset = 0;

    if (!ctx.data_size) {
        LOG_WARN("Data to write is of size 0");
    }

    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TPM2B_NAME nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    bool res = tpm2_util_nv_read_public(sapi_context, ctx.nv_index, &nv_public,
                &nv_name);
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

    while (ctx.data_size > 0) {

        nv_write_data.size =
                ctx.data_size > max_data_size ?
                        max_data_size : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.size);

        memcpy(nv_write_data.buffer, &ctx.nv_buffer[data_offset], nv_write_data.size);

        if (ctx.auth.is_hmac_auth) {
             TPM2B_NAME entity_1_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
            if (!tpm2_hmac_auth_get_entity_name(sapi_context, ctx.auth.hierarchy,
                                 &entity_1_name)) {
                LOG_ERR("Entity name calculation error.");
                return false;
            }
        
            TPM2B_NAME entity_2_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
            if (!tpm2_hmac_auth_get_entity_name(sapi_context, ctx.nv_index,
                    &entity_2_name)) {
                LOG_ERR("Entity name calculation error.");
                return false;
            }

            TSS2_RC rval = TSS2_RETRY_EXP( Tss2_Sys_NV_Write_Prepare(sapi_context,
                            ctx.auth.hierarchy, ctx.nv_index, &nv_write_data,
                            ctx.offset + data_offset));
            if (rval != TPM2_RC_SUCCESS) {
                LOG_ERR("Failed to prepare write NV area at index 0x%X", ctx.nv_index);
                LOG_PERR(Tss2_Sys_NV_Write, rval);
                return false;
            }
    
            uint8_t hmac_session_cnt = 0;
            int i=0;
            for (i = 0; i < ctx.auth.auth_list.count; i++) {
                if (TPM2_SE_HMAC==tpm2_session_get_type(ctx.auth.session[i])
                    && hmac_session_cnt < 2) {
                    tpm2_hmac_auth_get_command_buffer_hmac(sapi_context, ctx.auth.hierarchy,
                        ctx.auth.session[hmac_session_cnt], &ctx.auth.auth_list.auths[i], 
                        entity_1_name, entity_2_name);
                }
            }
        }

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_NV_Write(sapi_context,
            ctx.auth.hierarchy, ctx.nv_index, &ctx.auth.auth_list,
            &nv_write_data, ctx.offset + data_offset, &sessions_data_out));
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
        result = tpm2_auth_util_from_optarg_new(value, &ctx.auth.auth_list,
            ctx.auth.session_data[ctx.auth.auth_list.count],
            &ctx.auth.session[ctx.auth.auth_list.count], &ctx.auth.is_hmac_auth);
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
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        tpm2_session_set_type_in_session_data(ctx.auth.session_data[ctx.auth.auth_list.count],
            TPM2_SE_POLICY);
        ctx.auth.auth_list.count += 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
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
        { "index",          required_argument, NULL, 'x' },
        { "hierarchy",      required_argument, NULL, 'a' },
        { "auth-hierarchy", required_argument, NULL, 'P' },
        { "offset",         required_argument, NULL, 'o' },
        { "set-list",       required_argument, NULL, 'L' },
        { "pcr-input-file", required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("x:a:P:o:L:F:", ARRAY_LEN(topts), topts,
                             on_option, on_args, 0);

    ctx.input_file = stdin;

    int i=0;
    for (i = 0; i < 3; i++) {
        ctx.auth.session_data[i] = tpm2_session_data_new(0);
    }

    return *opts != NULL;
}

#define INVALID_SESSION_TYPE 0xFF
static bool start_auth_session(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2_SE type =  INVALID_SESSION_TYPE;
    uint8_t hmac_session_cnt = 0;
    int i=0;
    for (i = 0; i < ctx.auth.auth_list.count; i++) {

        type = tpm2_session_get_type_from_session_data(ctx.auth.session_data[i]);
        bool result = false;
        switch(type) {
            case TPM2_SE_POLICY:
                ctx.auth.session[i] = tpm2_session_new(sapi_context,
                    ctx.auth.session_data[i]);
                if (!ctx.auth.session[i]) {
                    LOG_ERR("Could not start tpm session");
                    return false;
                }
                result = tpm2_policy_build_pcr(sapi_context,
                    ctx.auth.session[i], ctx.raw_pcrs_file,
                    &ctx.pcr_selection);
                if (!result) {
                    LOG_ERR("Could not build a pcr policy");
                    return false;
                }
                break;
            case TPM2_SE_HMAC:
                if (ctx.auth.is_hmac_auth &&
                    hmac_session_cnt >= 2) {
                    LOG_ERR("Max HMAC auth sessions reached");
                    return false;
                }
                hmac_session_cnt++;
                ctx.auth.session[i] = tpm2_session_new(sapi_context,
                    ctx.auth.session_data[i]);
                if (!ctx.auth.session[i]) {
                    LOG_ERR("Could not start tpm session");
                    return false;
                }
                break;
            default:
                LOG_ERR("Invalid/ Unsupported session type %08X", type);
                return false;
        }

        ctx.auth.auth_list.auths[i].sessionHandle = 
                tpm2_session_get_handle(ctx.auth.session[i]);
        ctx.auth.auth_list.auths[i].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    }

    return true;
}


int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    uint8_t policy_session_count = 0;
    uint8_t hmac_session_count = 0;
    TPM2_SE type = INVALID_SESSION_TYPE;
    int i=0;
    for (i = 0; i < ctx.auth.auth_list.count; i++) {
        type = tpm2_session_get_type_from_session_data(ctx.auth.session_data[i]);
        switch(type) {
            case TPM2_SE_HMAC:
                hmac_session_count++;
                break;
            case TPM2_SE_POLICY:
                policy_session_count++;
                break;
            default:
                LOG_ERR("Invalid/ Unsupported session type %08X", type);
                goto out;
        }
    }

    if (policy_session_count > 1) {
        LOG_ERR("Can only use either existing session or a new session,"
                " not both!");
        goto out;
    }

    if (hmac_session_count > 1) {
        LOG_ERR("Can only use one HMAC authentication for this tool");
        goto out;
    }

    if (ctx.flags.L || ctx.auth.is_hmac_auth) {
        result = start_auth_session(sapi_context);
        if (!result) {
            goto out;
        }
    }

    if (!ctx.auth.auth_list.count) {
        ctx.auth.auth_list.auths[ctx.auth.auth_list.count++].sessionHandle =
            TPM2_RS_PW;
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
    for (i = 0; i < ctx.auth.auth_list.count; i++) {
        if(TPM2_SE_POLICY ==
            tpm2_session_get_type_from_session_data(ctx.auth.session_data[i])) {
            if (ctx.flags.L) {
                TSS2_RC rval = Tss2_Sys_FlushContext(sapi_context,
                        ctx.auth.auth_list.auths[i].sessionHandle);
                if (rval != TPM2_RC_SUCCESS) {
                    LOG_PERR(Tss2_Sys_FlushContext, rval);
                    rc = 1;
                }
            } else {
                result = tpm2_session_save(sapi_context,
                    ctx.auth.session[i], NULL);
                if (!result) {
                    rc = 1;
                }
            }
        }
    }

    return rc;
}

void tpm2_onexit(void) {
    int i=0;
    for (i = 0; i < ctx.auth.auth_list.count; i++) {
        if(TPM2_SE_POLICY ==
            tpm2_session_get_type_from_session_data(ctx.auth.session_data[i])) {
            tpm2_session_free(&ctx.auth.session[i]);
        }
    }
}
