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
#include <string.h>

#include <sapi/tpm20.h>

#include "tpm2_options.h"
#include "files.h"
#include "log.h"
#include "conversion.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_readpub_ctx tpm_readpub_ctx;
struct tpm_readpub_ctx {
    struct {
        UINT8 H      : 1;
        UINT8 o      : 1;
        UINT8 c      : 1;
        UINT8 f      : 1;
        UINT8 unused : 4;
    } flags;
    TPMI_DH_OBJECT objectHandle;
    char *outFilePath;
    char *context_file;
    pubkey_format format;
};

static tpm_readpub_ctx ctx = {
    .format = pubkey_format_tss
};

static int read_public_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    TPMS_AUTH_RESPONSE session_out_data;
    TSS2_SYS_RSP_AUTHS sessions_out_data;
    TPMS_AUTH_RESPONSE *session_out_data_array[1];

    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    session_out_data_array[0] = &session_out_data;
    sessions_out_data.rspAuths = &session_out_data_array[0];
    sessions_out_data.rspAuthsCount = ARRAY_LEN(session_out_data_array);

    TPM_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ReadPublic(sapi_context, ctx.objectHandle, 0,
            &public, &name, &qualified_name, &sessions_out_data));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_ReadPublic error: rval = 0x%0x", rval);
        return false;
    }

    tpm2_tool_output("name:");
    UINT16 i;
    for (i = 0; i < name.size; i++) {
        tpm2_tool_output("%02x", name.name[i]);
    }
    tpm2_tool_output("\n");

    tpm2_tool_output("qualified_name:");
    for (i = 0; i < qualified_name.size; i++) {
        tpm2_tool_output("%02x", qualified_name.name[i]);
    }
    tpm2_tool_output("\n");

    return tpm2_convert_pubkey(&public, ctx.format, ctx.outFilePath);
}

static bool on_option(char key, char *value) {

    bool result;
    switch (key) {
    case 'H':
        result = tpm2_util_string_to_uint32(value, &ctx.objectHandle);
        if (!result) {
            return false;
        }
        ctx.flags.H = 1;
        break;
    case 'o':
        ctx.outFilePath = optarg;
        ctx.flags.o = 1;
        break;
    case 'c':
        ctx.context_file = optarg;
        ctx.flags.c = 1;
        break;
    case 'f':
        ctx.format = tpm2_parse_pubkey_format(optarg);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "object",        required_argument, NULL,'H' },
        { "opu",           required_argument, NULL,'o' },
        { "context-object", required_argument, NULL,'c' },
        { "format",        required_argument, NULL,'f' }
    };

    *opts = tpm2_options_new("H:o:c:f:", ARRAY_LEN(topts), topts,
            on_option, NULL);

    return *opts != NULL;
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {

    if (!((ctx.flags.H || ctx.flags.c) && ctx.flags.o)) {
        return false;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_file(sapi_context, &ctx.objectHandle,
                ctx.context_file);
        if (!result) {
            return false;
        }
    }

    return true;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = init(sapi_context);
    if (!result) {
        return 1;
    }

    return read_public_and_save(sapi_context) != true;
}
