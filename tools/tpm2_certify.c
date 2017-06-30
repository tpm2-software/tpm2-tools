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

#include <getopt.h>
#include <limits.h>
#include <sapi/tpm20.h>

#include "../lib/tpm2_util.h"
#include "log.h"
#include "files.h"
#include "main.h"
#include "options.h"
#include "password_util.h"

typedef struct tpm_certify_ctx tpm_certify_ctx;
struct tpm_certify_ctx {
    TPMS_AUTH_COMMAND cmd_auth[2];
    TPMI_ALG_HASH  halg;
    struct  {
        TPMI_DH_OBJECT key;
        TPMI_DH_OBJECT obj;
    } handle;

    struct {
        char attest[PATH_MAX];
        char sig[PATH_MAX];
    } file_path;
    TSS2_SYS_CONTEXT *sapi_context;
};

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

static bool get_key_type(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT object_handle, TPMI_ALG_PUBLIC *type) {

    TPMS_AUTH_RESPONSE session_data_out;
    TPMS_AUTH_RESPONSE *session_data_out_array[] = {
        &session_data_out
    };

    TSS2_SYS_RSP_AUTHS sessions_data_out = {
            .rspAuthsCount = ARRAY_LEN(session_data_out_array),
            .rspAuths = session_data_out_array
    };

    TPM2B_PUBLIC out_public = {
            { 0, }
    };

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM_RC rval = Tss2_Sys_ReadPublic(sapi_context, object_handle, 0,
            &out_public, &name, &qualified_name, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_ReadPublic failed. Error Code: 0x%x", rval);
        return false;
    }

    *type = out_public.t.publicArea.type;

    return true;
}

static bool set_scheme(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT key_handle,
        TPMI_ALG_HASH halg, TPMT_SIG_SCHEME *scheme) {

    TPM_ALG_ID type;
    bool result = get_key_type(sapi_context, key_handle, &type);
    if (!result) {
        return false;
    }

    switch (type) {
    case TPM_ALG_RSA :
        scheme->scheme = TPM_ALG_RSASSA;
        scheme->details.rsassa.hashAlg = halg;
        break;
    case TPM_ALG_KEYEDHASH :
        scheme->scheme = TPM_ALG_HMAC;
        scheme->details.hmac.hashAlg = halg;
        break;
    case TPM_ALG_ECC :
        scheme->scheme = TPM_ALG_ECDSA;
        scheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM_ALG_SYMCIPHER :
    default:
        LOG_ERR("Unknown key type, got: 0x%x", type);
        return false;
    }

    return true;
}

static bool certify_and_save_data(tpm_certify_ctx *ctx) {

    TPMS_AUTH_COMMAND *cmd_session_array[ARRAY_LEN(ctx->cmd_auth)] = {
        &ctx->cmd_auth[0],
        &ctx->cmd_auth[1]
    };

    TSS2_SYS_CMD_AUTHS cmd_auth_array = {
        .cmdAuthsCount = ARRAY_LEN(cmd_session_array),
        .cmdAuths = cmd_session_array
    };

    TPMS_AUTH_RESPONSE session_data_out[ARRAY_LEN(ctx->cmd_auth)];
    TPMS_AUTH_RESPONSE *session_data_array[] = {
        &session_data_out[0],
        &session_data_out[1]
    };

    TSS2_SYS_RSP_AUTHS sessions_data_out = {
        .rspAuthsCount = ARRAY_LEN(session_data_array),
        .rspAuths = session_data_array
    };

    TPM2B_DATA qualifying_data = {
        .t = {
            .size = 4,
            .buffer = { 0x00, 0xff, 0x55,0xaa }
        }
    };

    TPMT_SIG_SCHEME scheme;
    bool result = set_scheme(ctx->sapi_context, ctx->handle.key, ctx->halg, &scheme);
    if (!result) {
        LOG_ERR("No suitable signing scheme!\n");
        return false;
    }

    TPM2B_ATTEST certify_info = {
        .t = {
            .size = sizeof(certify_info)-2
        }
    };

    TPMT_SIGNATURE signature;

    TPM_RC rval = Tss2_Sys_Certify(ctx->sapi_context, ctx->handle.obj,
            ctx->handle.key, &cmd_auth_array, &qualifying_data, &scheme,
            &certify_info, &signature, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Certify failed. Error Code: 0x%x", rval);
        return false;
    }

    /* serialization is safe here, since it's just a byte array */
    result = files_save_bytes_to_file(ctx->file_path.attest,
            (UINT8 *) certify_info.t.attestationData, certify_info.t.size);
    if (!result) {
        return false;
    }

    /* TODO serialization is not safe here */
    return files_save_bytes_to_file(ctx->file_path.sig, (UINT8 *) &signature,
            sizeof(signature));
}

static bool check_and_set_file(const char *path, char *dest, size_t dest_size) {

    bool result = files_does_file_exist(path);
    if (result) {
        return false;
    }
    snprintf(dest, dest_size, "%s", path);
    return true;
}

static bool init(int argc, char *argv[], tpm_certify_ctx *ctx) {

    bool result = false;
    bool is_hex_password = false;

    char *context_file = NULL;
    char *context_key_file = NULL;

    const char *optstring = "H:k:P:K:g:a:s:C:c:X";
    static struct option long_options[] = {
      {"objectHandle", required_argument, NULL, 'H'},
      {"keyHandle",    required_argument, NULL, 'k'},
      {"pwdo",         required_argument, NULL, 'P'},
      {"pwdk",         required_argument, NULL, 'K'},
      {"halg",         required_argument, NULL, 'g'},
      {"attestFile",   required_argument, NULL, 'a'},
      {"sigFile",      required_argument, NULL, 's'},
      {"objContext",   required_argument, NULL, 'C'},
      {"keyContext",   required_argument, NULL, 'c'},
      {"passwdInHex",  no_argument,       NULL, 'X'},
      {NULL,           no_argument,       NULL, '\0'}
    };

    struct {
        UINT16 H : 1;
        UINT16 k : 1;
        UINT16 P : 1;
        UINT16 K : 1;
        UINT16 g : 1;
        UINT16 a : 1;
        UINT16 s : 1;
        UINT16 C : 1;
        UINT16 c : 1;
        UINT16 unused : 7;
    } flags = { 0 };


    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt = -1;

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'H':
            result = tpm2_util_string_to_uint32(optarg, &ctx->handle.obj);
            if (!result) {
                LOG_ERR("Could not format object handle to number, got: \"%s\"",
                        optarg);
                goto out;
            }
            flags.H = 1;
            break;
        case 'k':
            result = tpm2_util_string_to_uint32(optarg, &ctx->handle.key);
            if (!result) {
                LOG_ERR("Could not format key handle to number, got: \"%s\"",
                        optarg);
                goto out;
            }
            flags.k = 1;
            break;
        case 'P':
            result = password_tpm2_util_copy_password(optarg, "object handle",
                    &ctx->cmd_auth[0].hmac);
            if (!result) {
                goto out;
            }
            flags.P = 1;
            break;
        case 'K':
            result = password_tpm2_util_copy_password(optarg, "key handle",
                    &ctx->cmd_auth[1].hmac);
            if (!result) {
                goto out;
            }
            flags.K = 1;
            break;
        case 'g':
            result = tpm2_util_string_to_uint16(optarg, &ctx->halg);
            if (!result) {
                LOG_ERR("Could not format algorithm to number, got: \"%s\"",
                        optarg);
                goto out;
            }
            flags.g = 1;
            break;
        case 'a':
            result = check_and_set_file(optarg, ctx->file_path.attest,
                    sizeof(ctx->file_path.attest));
            if (!result) {
                goto out;
            }
            flags.a = 1;
            break;
        case 's':
            result = check_and_set_file(optarg, ctx->file_path.sig,
                    sizeof(ctx->file_path.sig));
            if (!result) {
                goto out;
            }
            flags.s = 1;
            break;
        case 'c':
            if (context_key_file) {
                LOG_ERR("Multiple specifications of -c");
                goto out;
            }
            context_key_file = strdup(optarg);
            if (!context_key_file) {
                LOG_ERR("oom");
                goto out;
            }
            flags.c = 1;
            break;
        case 'C':
            if (context_file) {
                LOG_ERR("Multiple specifications of -C");
                goto out;
            }
            context_file = strdup(optarg);
            if (!context_file) {
                LOG_ERR("oom");
                goto out;
            }
            flags.C = 1;
            break;
        case 'X':
            is_hex_password = true;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            result = false;
            goto out;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            result = false;
            goto out;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            result = false;
            goto out;
        }
    };

    if (!(flags.H || flags.C) && (flags.k || flags.c) && (flags.g) && (flags.a)
            && (flags.s)) {
        result = false;
        goto out;
    }

    /* convert a hex passwords if needed */
    result = password_tpm2_util_to_auth(&ctx->cmd_auth[0].hmac, is_hex_password,
            "object handle", &ctx->cmd_auth[0].hmac);
    if (!result) {
        goto out;
    }

    result = password_tpm2_util_to_auth(&ctx->cmd_auth[1].hmac, is_hex_password,
            "key handle", &ctx->cmd_auth[1].hmac);
    if (!result) {
        goto out;
    }

    /* Finish initialize the cmd_auth array */
    ctx->cmd_auth[0].sessionHandle = TPM_RS_PW;
    ctx->cmd_auth[1].sessionHandle = TPM_RS_PW;
    *((UINT8 *) ((void *) &ctx->cmd_auth[0].sessionAttributes)) = 0;
    *((UINT8 *) ((void *) &ctx->cmd_auth[0].sessionAttributes)) = 0;

    /* Load input files */
    if (flags.C) {
        result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->handle.obj,
                context_file);
        if (!result) {
            goto out;
        }
    }

    if (flags.c) {
        result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->handle.key,
                context_key_file);
        if (!result) {
            goto out;
        }
    }

    result = true;

out:
    free(context_file);
    free(context_key_file);

    return result;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    tpm_certify_ctx ctx = {
            .cmd_auth = {
                { .sessionHandle = TPM_RS_PW, .sessionAttributes = { .val = 0 } }, // [0]
                { .sessionHandle = TPM_RS_PW, .sessionAttributes = { .val = 0 } }  // [1]
            },
            .file_path = { .attest = { 0 }, .sig = { 0 } },
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return false;
    }

    return certify_and_save_data(&ctx) != true;
}
