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

#include <tss2/tss2_esys.h>

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
        UINT8 p : 1;
        UINT8 I : 1;
        UINT8 o : 1;
        UINT8 unused : 3;
    } flags;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *output_file_path;
    char *key_auth_str;
    const char *context_arg;
    tpm2_loaded_object key_context_object;
};

tpm_rsadecrypt_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) }
};

static bool rsa_decrypt_and_save(ESYS_CONTEXT *ectx) {

    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA *message;

    inScheme.scheme = TPM2_ALG_RSAES;
    label.size = 0;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.key_context_object.tr_handle,
                            &ctx.auth.session_data, ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        return false;
    }

    TSS2_RC rval = Esys_RSA_Decrypt(ectx, ctx.key_context_object.tr_handle,
                        shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                        &ctx.cipher_text, &inScheme, &label, &message);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_RSA_Decrypt, rval);
        return false;
    }

    bool ret = files_save_bytes_to_file(ctx.output_file_path, message->buffer,
                    message->size);

    free(message);

    return ret;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'p':
        ctx.flags.p = 1;
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
        ctx.output_file_path = value;
        ctx.flags.o = 1;
        break;
    }
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "auth-key",     required_argument, NULL, 'p' },
      { "in-file",      required_argument, NULL, 'I' },
      { "out-file",     required_argument, NULL, 'o' },
      { "key-context",  required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("p:I:o:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static bool init(ESYS_CONTEXT *ectx) {


    if (!(ctx.context_arg && ctx.flags.I && ctx.flags.o)) {
        LOG_ERR("Expected arguments I, o and c.");
        return false;
    }

    bool result = tpm2_util_object_load(ectx, ctx.context_arg,
                    &ctx.key_context_object);
    if (!result) {
        return false;
    }

   return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init(ectx);
    if (!result) {
        goto out;
    }

    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.key_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.key_auth_str);
            goto out;
        }
    }

    result = rsa_decrypt_and_save(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_session_save(ectx, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    tpm2_session_free(&ctx.auth.session);

    return rc;
}
