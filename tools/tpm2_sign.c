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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <sapi/tpm20.h>

#include "tpm2_password_util.h"
#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"
#include "tpm_hash.h"
#include "tpm2_alg_util.h"

typedef struct tpm_sign_ctx tpm_sign_ctx;
struct tpm_sign_ctx {
    TPMT_TK_HASHCHECK validation;
    TPMS_AUTH_COMMAND sessionData;
    TPMI_DH_OBJECT keyHandle;
    TPMI_ALG_HASH halg;
    char *outFilePath;
    BYTE *msg;
    UINT16 length;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool get_key_type(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT objectHandle,
        TPMI_ALG_PUBLIC *type) {

    TPMS_AUTH_RESPONSE session_data_out;

    TPMS_AUTH_RESPONSE *session_data_out_array[1] = {
            &session_data_out
    };

    TSS2_SYS_RSP_AUTHS sessions_data_out = {
            1,
            &session_data_out_array[0]
    };

    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_NAME qaulified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM_RC rval = Tss2_Sys_ReadPublic(sapi_context, objectHandle, 0, &out_public, &name,
            &qaulified_name, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Sys_ReadPublic failed, error code: 0x%x", rval);
        return false;
    }
    *type = out_public.t.publicArea.type;
    return true;
}

static bool set_scheme(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT keyHandle,
        TPMI_ALG_HASH halg, TPMT_SIG_SCHEME *inScheme) {

    TPM_ALG_ID type;
    bool result = get_key_type(sapi_context, keyHandle, &type);
    if (!result) {
        return false;
    }

    switch (type) {
    case TPM_ALG_RSA :
        inScheme->scheme = TPM_ALG_RSASSA;
        inScheme->details.rsassa.hashAlg = halg;
        break;
    case TPM_ALG_KEYEDHASH :
        inScheme->scheme = TPM_ALG_HMAC;
        inScheme->details.hmac.hashAlg = halg;
        break;
    case TPM_ALG_ECC :
        inScheme->scheme = TPM_ALG_ECDSA;
        inScheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM_ALG_SYMCIPHER :
    default:
        LOG_ERR("Unknown key type, got: 0x%x", type);
        return false;
    }

    return true;
}

static bool sign_and_save(tpm_sign_ctx *ctx) {

    TPM2B_DIGEST digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPMT_SIG_SCHEME in_scheme;
    TPMT_SIGNATURE signature;

    TSS2_SYS_CMD_AUTHS sessions_data;
    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    session_data_array[0] = &ctx->sessionData;
    sessions_data.cmdAuths = &session_data_array[0];
    session_data_out_array[0] = &session_data_out;
    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    int rc = tpm_hash_compute_data(ctx->sapi_context, ctx->msg, ctx->length,
            ctx->halg, &digest);
    if (rc) {
        LOG_ERR("Compute message hash failed!");
        return false;
    }

//    printf("\ndigest(hex type):\n ");
//    UINT16 i;
//    for (i = 0; i < digest.t.size; i++)
//        printf("%02x ", digest.t.buffer[i]);
//    printf("\n");

    bool result = set_scheme(ctx->sapi_context, ctx->keyHandle, ctx->halg, &in_scheme);
    if (!result) {
        return false;
    }

    TPM_RC rval = Tss2_Sys_Sign(ctx->sapi_context, ctx->keyHandle,
            &sessions_data, &digest, &in_scheme, &ctx->validation, &signature,
            &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Sys_Sign failed, error code: 0x%x", rval);
        return false;
    }

    /* TODO fix serialization */
    return files_save_bytes_to_file(ctx->outFilePath, (UINT8 *) &signature,
            sizeof(signature));
}

static bool init(int argc, char *argv[], tpm_sign_ctx *ctx) {

    static const char *optstring = "k:P:g:m:t:s:c:S:";
    static const struct option long_options[] = {
      {"keyHandle",1,NULL,'k'},
      {"pwdk",1,NULL,'P'},
      {"halg",1,NULL,'g'},
      {"msg",1,NULL,'m'},
      {"sig",1,NULL,'s'},
      {"ticket",1,NULL,'t'},
      {"keyContext",1,NULL,'c'},
      {"input-session-handle",1,NULL, 'S' },
      {0,0,0,0}
    };

    if(argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    union {
        struct {
            UINT8 k : 1;
            UINT8 P : 1;
            UINT8 g : 1;
            UINT8 m : 1;
            UINT8 t : 1;
            UINT8 s : 1;
            UINT8 c : 1;
            UINT8 unused : 1;
        };
        UINT8 all;
    } flags = { .all = 0 };

    int opt;
    char *contextKeyFile = NULL;
    char *inMsgFileName = NULL;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        case 'k': {
            bool result = tpm2_util_string_to_uint32(optarg, &ctx->keyHandle);
            if (!result) {
                LOG_ERR("Could not format key handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
            flags.k = 1;
        }
            break;
        case 'P': {
            bool result = tpm2_password_util_from_optarg(optarg, &ctx->sessionData.hmac);
            if (!result) {
                LOG_ERR("Invalid key password, got\"%s\"", optarg);
                return false;
            }
            flags.P = 1;
        }
            break;
        case 'g': {
            ctx->halg = tpm2_alg_util_from_optarg(optarg);
            if (ctx->halg == TPM_ALG_ERROR) {
                LOG_ERR("Could not convert to number or lookup algorithm, got: \"%s\"",
                        optarg);
                return false;
            }
            flags.g = 1;
        }
            break;
        case 'm':
            inMsgFileName = optarg;
            flags.m = 1;
            break;
        case 't': {
            UINT16 size = sizeof(ctx->validation);
            bool result = files_load_bytes_from_file(optarg, (UINT8 *) &ctx->validation,
                    &size);
            if (!result) {
                return false;
            }
            flags.t = 1;
        }
            break;
        case 's': {
            bool result = files_does_file_exist(optarg);
            if (result) {
                return false;
            }
            ctx->outFilePath = optarg;
            flags.s = 1;
        }
            break;
        case 'c':
            contextKeyFile = optarg;
            flags.c = 1;
            break;
        case 'S':
            if (!tpm2_util_string_to_uint32(optarg, &ctx->sessionData.sessionHandle)) {
                LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                        optarg);
                return false;
            }
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

    if (!((flags.k || flags.c) && flags.m && flags.s)) {
        LOG_ERR("Expected options (k or c) and m and s");
        return false;
    }

    if (!flags.t) {
        ctx->validation.tag = TPM_ST_HASHCHECK;
        ctx->validation.hierarchy = TPM_RH_NULL;
    }

    /*
     * load tpm context from a file if -c is provided
     */
    if (flags.c) {
        bool result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->keyHandle,
                contextKeyFile);
        if (!result) {
            return false;
        }
    }

    /*
     * Process the msg file
     */
    unsigned long file_size;
    bool result = files_get_file_size(inMsgFileName, &file_size);
    if (!result) {
        return false;
    }
    if (file_size == 0) {
        LOG_ERR("The message file \"%s\" is empty!", inMsgFileName);
        return false;
    }

    if (file_size > 0xffff) {
        LOG_ERR(
                "The message file was longer than a 16 bit length, got: %lu, expected less than: %d!",
                file_size, 0x10000);
        return false;
    }

    ctx->msg = (BYTE*) calloc(1, file_size);
    if (!ctx->msg) {
        LOG_ERR("oom");
        return false;
    }

    ctx->length = file_size;
    result = files_load_bytes_from_file(inMsgFileName, ctx->msg, &ctx->length);
    if (!result) {
        free(ctx->msg);
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts and envp are unused, avoid compiler warning */
    (void)opts;
    (void) envp;

    tpm_sign_ctx ctx = {
            .msg = NULL,
            .sessionData = TPMS_AUTH_COMMAND_EMPTY_INIT,
            .halg = TPM_ALG_SHA1,
            .keyHandle = 0,
            .validation = TPMT_TK_HASHCHECK_EMPTY_INIT,
            .sapi_context = sapi_context
    };

    ctx.sessionData.sessionHandle = TPM_RS_PW;

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    result = sign_and_save(&ctx);

    free(ctx.msg);

    return result != true;
}
