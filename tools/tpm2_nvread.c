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
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>

#include <sapi/tpm20.h>

#include "../lib/tpm2_password_util.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_nv_util.h"
#include "tpm2_util.h"

typedef struct tpm_nvread_ctx tpm_nvread_ctx;
struct tpm_nvread_ctx {
    UINT32 nv_index;
    UINT32 auth_handle;
    UINT32 size_to_read;
    UINT32 offset;
    TPM2B_AUTH handle_passwd;
    bool is_hex_password;
    TSS2_SYS_CONTEXT *sapi_context;
    bool is_auth_session;
    TPMI_SH_AUTH_SESSION auth_session_handle;
};

static void hexdump(void *ptr, unsigned buflen) {

    unsigned char *buf = (unsigned char*) ptr;
    unsigned i, j;

    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                printf("%02x ", buf[i + j]);
            } else {
                printf("   ");
            }
        }
        printf(" ");
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}

static bool nv_read(tpm_nvread_ctx *ctx) {

    TPMS_AUTH_COMMAND session_data = TPMS_AUTH_COMMAND_EMPTY_INIT;
    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;

    TPM2B_MAX_NV_BUFFER nv_data = TPM2B_TYPE_INIT(TPM2B_MAX_NV_BUFFER, buffer);

    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    session_data_array[0] = &session_data;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    session_data.sessionHandle = TPM_RS_PW;
    if (ctx->is_auth_session) {
        session_data.sessionHandle = ctx->auth_session_handle;
    }

    bool result = tpm2_password_util_fromhex(&ctx->handle_passwd, ctx->is_hex_password,
            "handle password", &session_data.hmac);
    if (!result) {
        return false;
    }

    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TPM_RC rval = tpm2_util_nv_read_public(ctx->sapi_context, ctx->nv_index, &nv_public);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed to read NVRAM public area at index 0x%x (%d). Error:0x%x",
                ctx->nv_index, ctx->nv_index, rval);
        return false;
    }

    UINT16 data_size = nv_public.t.nvPublic.dataSize;

    /* if no size was specified, assume the whole object */
    if (ctx->size_to_read == 0) {
        ctx->size_to_read = data_size;
    }

    if (ctx->offset > data_size) {
        LOG_ERR(
            "Requested offset to read from is greater than size. offset=%u"
            ", size=%u", ctx->offset, data_size);
        return false;
    }

    if (ctx->offset + ctx->size_to_read > data_size) {
        LOG_WARN(
            "Requested to read more bytes than available from offset,"
            " truncating read! offset=%u, request-read-size=%u"
            " actual-data-size=%u", ctx->offset, ctx->size_to_read, data_size);
        ctx->size_to_read = data_size - ctx->offset;
        return false;
    }


    UINT8 *data_buffer = malloc(data_size);
    if (!data_buffer) {
        LOG_ERR("oom");
        return false;
    }

    result = false;
    UINT16 data_offest = 0;
    while (ctx->size_to_read) {

        UINT16 bytes_to_read = ctx->size_to_read > MAX_NV_BUFFER_SIZE ?
                        MAX_NV_BUFFER_SIZE : ctx->size_to_read;

        rval = Tss2_Sys_NV_Read(ctx->sapi_context, ctx->auth_handle, ctx->nv_index,
                &sessions_data, bytes_to_read, ctx->offset, &nv_data, &sessions_data_out);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed to read NVRAM area at index 0x%x (%d). Error:0x%x",
                    ctx->nv_index, ctx->nv_index, rval);
            goto out;
        }

        ctx->size_to_read -= nv_data.t.size;
        ctx->offset += nv_data.t.size;

        memcpy(data_buffer, nv_data.t.buffer, data_offest);
        data_offest += nv_data.t.size;
    }

    hexdump(data_buffer, data_size);
    result = true;

out:
    free(data_buffer);
    return result;
}

static bool init(int argc, char *argv[], tpm_nvread_ctx *ctx) {

    struct option long_options[] = {
        { "index"       , required_argument, NULL, 'x' },
        { "authHandle"  , required_argument, NULL, 'a' },
        { "size"        , required_argument, NULL, 's' },
        { "offset"      , required_argument, NULL, 'o' },
        { "handlePasswd", required_argument, NULL, 'P' },
        { "passwdInHex" , no_argument,       NULL, 'X' },
        { "input-session-handle",1,          NULL, 'S' },
        { NULL          , no_argument,       NULL, 0   },
    };

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, "x:a:s:o:P:S:X", long_options, NULL))
            != -1) {
        switch (opt) {
        case 'x':
            result = tpm2_util_string_to_uint32(optarg, &ctx->nv_index);
            if (!result) {
                LOG_ERR("Could not convert NV index to number, got: \"%s\"",
                        optarg);
                return false;
            }

            if (ctx->nv_index == 0) {
                LOG_ERR("NV Index cannot be 0");
                return false;
            }

            break;
        case 'a':
            result = tpm2_util_string_to_uint32(optarg, &ctx->auth_handle);
            if (!result) {
                LOG_ERR("Could not convert auth handle to number, got: \"%s\"",
                        optarg);
                return false;
            }

            if (ctx->auth_handle == 0) {
                LOG_ERR("Auth handle cannot be 0");
                return false;
            }
            break;
        case 'P':
            result = tpm2_password_util_copy_password(optarg, "handle password",
                    &ctx->handle_passwd);
            if (!result) {
                return false;
            }
            break;
        case 's':
            result = tpm2_util_string_to_uint32(optarg, &ctx->size_to_read);
            if (!result) {
                LOG_ERR("Could not convert size to number, got: \"%s\"",
                        optarg);
                return false;
            }
            break;
        case 'o':
            result = tpm2_util_string_to_uint32(optarg, &ctx->offset);
            if (!result) {
                LOG_ERR("Could not convert offset to number, got: \"%s\"",
                        optarg);
                return false;
            }
            break;
        case 'X':
            ctx->is_hex_password = true;
            break;
        case 'S':
             if (!tpm2_util_string_to_uint32(optarg, &ctx->auth_session_handle)) {
                 LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                         optarg);
                 return false;
             }
             ctx->is_auth_session = true;
             break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            return false;
        }
    }
    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    tpm_nvread_ctx ctx = {
            .nv_index = 0,
            .auth_handle = TPM_RH_PLATFORM,
            .size_to_read = 0,
            .offset = 0,
            .handle_passwd = TPM2B_EMPTY_INIT,
            .is_hex_password = false,
            .sapi_context = sapi_context,
            .is_auth_session = false
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return nv_read(&ctx) != true;
}
