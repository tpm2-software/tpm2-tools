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

#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "files.h"
#include "log.h"
#include "tpm2_util.h"
#include "tpm_hash.h"
#include "tpm2_alg_util.h"
#include "conversion.h"

typedef struct tpm_sign_ctx tpm_sign_ctx;
struct tpm_sign_ctx {
    TPMT_TK_HASHCHECK validation;
    TPMS_AUTH_COMMAND sessionData;
    TPMI_DH_OBJECT keyHandle;
    TPMI_ALG_HASH halg;
    char *outFilePath;
    BYTE *msg;
    UINT16 length;
    char *contextKeyFile;
    char *inMsgFileName;
    signature_format sig_format;
    struct {
        UINT8 k : 1;
        UINT8 P : 1;
        UINT8 g : 1;
        UINT8 m : 1;
        UINT8 t : 1;
        UINT8 s : 1;
        UINT8 c : 1;
        UINT8 f : 1;
    } flags;
};

tpm_sign_ctx ctx = {
        .msg = NULL,
        .sessionData = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .halg = TPM2_ALG_SHA1,
};

static bool sign_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_DIGEST digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPMT_SIG_SCHEME in_scheme;
    TPMT_SIGNATURE signature;

    TSS2L_SYS_AUTH_COMMAND sessions_data = { 1, { ctx.sessionData }};
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    int rc = tpm_hash_compute_data(sapi_context, ctx.halg, TPM2_RH_NULL,
            ctx.msg, ctx.length, &digest, NULL);
    if (rc) {
        LOG_ERR("Compute message hash failed!");
        return false;
    }

    bool result = get_signature_scheme(sapi_context, ctx.keyHandle, ctx.halg, &in_scheme);
    if (!result) {
        return false;
    }

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(sapi_context, ctx.keyHandle,
            &sessions_data, &digest, &in_scheme, &ctx.validation, &signature,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Sys_Sign failed, error code: 0x%x", rval);
        return false;
    }

    return tpm2_convert_signature(&signature, ctx.sig_format, ctx.outFilePath);
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {

    if (!((ctx.flags.k || ctx.flags.c) && ctx.flags.m && ctx.flags.s)) {
        LOG_ERR("Expected options (k or c) and m and s");
        return false;
    }

    if (!ctx.flags.t) {
        ctx.validation.tag = TPM2_ST_HASHCHECK;
        ctx.validation.hierarchy = TPM2_RH_NULL;
    }

    /*
     * load tpm context from a file if -c is provided
     */
    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_file(sapi_context, &ctx.keyHandle,
                ctx.contextKeyFile);
        if (!result) {
            return false;
        }
    }

    /*
     * Process the msg file
     */
    unsigned long file_size;
    bool result = files_get_file_size_path(ctx.inMsgFileName, &file_size);
    if (!result) {
        return false;
    }
    if (file_size == 0) {
        LOG_ERR("The message file \"%s\" is empty!", ctx.inMsgFileName);
        return false;
    }

    if (file_size > 0xffff) {
        LOG_ERR(
                "The message file was longer than a 16 bit length, got: %lu, expected less than: %d!",
                file_size, 0x10000);
        return false;
    }

    ctx.msg = (BYTE*) calloc(required_argument, file_size);
    if (!ctx.msg) {
        LOG_ERR("oom");
        return false;
    }

    ctx.length = file_size;
    result = files_load_bytes_from_path(ctx.inMsgFileName, ctx.msg, &ctx.length);
    if (!result) {
        free(ctx.msg);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'k': {
        bool result = tpm2_util_string_to_uint32(value, &ctx.keyHandle);
        if (!result) {
            LOG_ERR("Could not format key handle to number, got: \"%s\"",
                    optarg);
            return false;
        }
        ctx.flags.k = 1;
    }
        break;
    case 'P': {
        bool result = tpm2_password_util_from_optarg(value, &ctx.sessionData.hmac);
        if (!result) {
            LOG_ERR("Invalid key password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.P = 1;
    }
        break;
    case 'g': {
        ctx.halg = tpm2_alg_util_from_optarg(optarg);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert to number or lookup algorithm, got: \"%s\"",
                    optarg);
            return false;
        }
        ctx.flags.g = 1;
    }
        break;
    case 'm':
        ctx.inMsgFileName = optarg;
        ctx.flags.m = 1;
        break;
    case 't': {
        bool result = files_load_validation(value, &ctx.validation);
        if (!result) {
            return false;
        }
        ctx.flags.t = 1;
    }
        break;
    case 's': {
        bool result = files_does_file_exist(optarg);
        if (result) {
            return false;
        }
        ctx.outFilePath = optarg;
        ctx.flags.s = 1;
    }
        break;
    case 'c':
        ctx.contextKeyFile = optarg;
        ctx.flags.c = 1;
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.sessionData.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    optarg);
            return false;
        }
        break;
    case 'f':
        ctx.flags.f = 1;
        ctx.sig_format = tpm2_parse_signature_format(optarg);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
    /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      {"key-handle",            required_argument, NULL, 'k'},
      {"pwdk",                 required_argument, NULL, 'P'},
      {"halg",                 required_argument, NULL, 'g'},
      {"msg",                  required_argument, NULL, 'm'},
      {"sig",                  required_argument, NULL, 's'},
      {"ticket",               required_argument, NULL, 't'},
      {"key-context",           required_argument, NULL, 'c'},
      {"input-session-handle", required_argument, NULL, 'S'},
      {"format",               required_argument, NULL, 'f'}
    };

    *opts = tpm2_options_new("k:P:g:m:t:s:c:S:f:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = init(sapi_context);
    if (!result) {
        return 1;
    }

    result = sign_and_save(sapi_context);

    free(ctx.msg);

    return result != true;
}
