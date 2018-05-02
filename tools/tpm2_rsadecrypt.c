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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    struct {
        UINT8 k : 1;
        UINT8 P : 1;
        UINT8 I : 1;
        UINT8 c : 1;
        UINT8 o : 1;
        UINT8 unused : 3;
    } flags;
    TPMI_DH_OBJECT key_handle;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *output_file_path;
    char *context_key_file;
    char *key_auth_str;
};

tpm_rsadecrypt_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) }
};

static bool rsa_decrypt_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA message = TPM2B_TYPE_INIT(TPM2B_PUBLIC_KEY_RSA, buffer);

    TSS2L_SYS_AUTH_COMMAND sessions_data = { 1, { ctx.auth.session_data }};
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    inScheme.scheme = TPM2_ALG_RSAES;
    label.size = 0;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_RSA_Decrypt(sapi_context, ctx.key_handle,
            &sessions_data, &ctx.cipher_text, &inScheme, &label, &message,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_RSA_Decrypt, rval);
        return false;
    }

    return files_save_bytes_to_file(ctx.output_file_path, message.buffer,
            message.size);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'k': {
        bool result = tpm2_util_string_to_uint32(value, &ctx.key_handle);
        if (!result) {
            LOG_ERR("Could not convert key handle to number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.k = 1;
    }
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.key_auth_str = value;
        break;
    case 'I': {
        ctx.cipher_text.size = sizeof(ctx.cipher_text) - 2;
        bool result = files_load_bytes_from_path(value, ctx.cipher_text.buffer,
                &ctx.cipher_text.size);
        if (!result) {
            return false;
        }
        ctx.flags.I = 1;
    }
        break;
    case 'o': {
        bool result = files_does_file_exist(value);
        if (result) {
            return false;
        }
        ctx.output_file_path = value;
        ctx.flags.o = 1;
    }
        break;
    case 'c':
        ctx.context_key_file = value;
        ctx.flags.c = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "key-handle",   required_argument, NULL, 'k' },
      { "auth-key",     required_argument, NULL, 'P' },
      { "in-file",      required_argument, NULL, 'I' },
      { "out-file",     required_argument, NULL, 'o' },
      { "key-context",  required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("k:P:I:o:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {


    if (!((ctx.flags.k || ctx.flags.c) && ctx.flags.I && ctx.flags.o)) {
        LOG_ERR("Expected arguments I and o and (k or c)");
        return false;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_path(sapi_context,
                &ctx.key_handle, ctx.context_key_file);
        if (!result) {
            return false;
        }
    }

   return true;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init(sapi_context);
    if (!result) {
        goto out;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.key_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.key_auth_str);
            goto out;
        }
    }

    result = rsa_decrypt_and_save(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_session_save(sapi_context, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_tool_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
