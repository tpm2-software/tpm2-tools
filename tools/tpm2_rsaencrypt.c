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
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_rsaencrypt_ctx tpm_rsaencrypt_ctx;
struct tpm_rsaencrypt_ctx {
    struct {
        UINT8 k : 1;
        UINT8 I : 1;
        UINT8 o : 1;
        UINT8 c : 1;
        UINT8 unused : 4;
    } flags;
    char *context_key_file;
    TPMI_DH_OBJECT key_handle;
    TPM2B_PUBLIC_KEY_RSA message;
    char *output_file_path;
};

static tpm_rsaencrypt_ctx ctx;

static bool rsa_encrypt_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    // Inputs
    TPMT_RSA_DECRYPT scheme;
    TPM2B_DATA label;
    // Outputs
    TPM2B_PUBLIC_KEY_RSA out_data = TPM2B_TYPE_INIT(TPM2B_PUBLIC_KEY_RSA, buffer);

    TPMS_AUTH_RESPONSE out_session_data;
    TSS2_SYS_RSP_AUTHS out_sessions_data;
    TPMS_AUTH_RESPONSE *out_session_data_array[1];

    out_session_data_array[0] = &out_session_data;
    out_sessions_data.rspAuths = &out_session_data_array[0];
    out_sessions_data.rspAuthsCount = 1;

    scheme.scheme = TPM_ALG_RSAES;
    label.t.size = 0;

    TPM_RC rval = Tss2_Sys_RSA_Encrypt(sapi_context, ctx.key_handle, NULL,
            &ctx.message, &scheme, &label, &out_data, &out_sessions_data);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("RSA_Encrypt failed, error code: 0x%x", rval);
        return false;
    }

    return files_save_bytes_to_file(ctx.output_file_path, out_data.t.buffer,
            out_data.t.size);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'k': {
        bool result = tpm2_util_string_to_uint32(value, &ctx.key_handle);
        if (!result) {
            LOG_ERR("Could not convert key handle to number, got: \"%s\"",
                    optarg);
            return false;
        }
        ctx.flags.k = 1;
    }
        break;
    case 'I': {
        ctx.message.t.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
        bool result = files_load_bytes_from_path(value, ctx.message.t.buffer,
                &ctx.message.t.size);
        if (!result) {
            return false;
        }
        ctx.flags.I = 1;
    }
        break;
    case 'o': {
        bool result = files_does_file_exist(optarg);
        if (result) {
            return false;
        }
        ctx.output_file_path = optarg;
        ctx.flags.o = 1;
    }
        break;
    case 'c':
        ctx.context_key_file = optarg;
        ctx.flags.c = 1;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      {"keyHandle",  required_argument, NULL, 'k'},
      {"inFile",     required_argument, NULL, 'I'},
      {"outFile",    required_argument, NULL, 'o'},
      {"keyContext", required_argument, NULL, 'c'},
    };

    *opts = tpm2_options_new("k:I:o:c:", ARRAY_LEN(topts), topts,
            on_option, NULL);

    return *opts != NULL;
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {

    if (!((ctx.flags.k || ctx.flags.c) && ctx.flags.I && ctx.flags.o)) {
        LOG_ERR("Expected options I and o and (k or c)");
        return false;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_file(sapi_context, &ctx.key_handle,
                ctx.context_key_file);
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

    return rsa_encrypt_and_save(sapi_context) != true;
}
