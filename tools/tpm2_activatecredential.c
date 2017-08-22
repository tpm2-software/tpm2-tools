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
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "tpm2_password_util.h"
#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"
#include "tpm_session.h"

typedef struct tpm_activatecred_ctx tpm_activatecred_ctx;
struct tpm_activatecred_ctx {

    struct {
        TPMI_DH_OBJECT activate;
        TPMI_DH_OBJECT key;
    } handle;

    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;

    TPMS_AUTH_COMMAND password;
    TPMS_AUTH_COMMAND endorse_password;

    struct {
        char *output;
        char *context;
        char *key_context;
    } file ;
};

static bool read_cert_secret(const char *path, TPM2B_ID_OBJECT *credentialBlob,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    size_t items = fread(credentialBlob, sizeof(TPM2B_ID_OBJECT), 1, fp);
    if (items != 1) {
        const char *fmt_msg =
                "Reading credential from file \"%s\" failed, error: \"%s\"";
        const char *err_msg = "Unknown error";
        if (ferror(fp)) {
            err_msg = strerror(errno);
        } else if (feof(fp)) {
            err_msg = "end of file";
        }
        LOG_ERR(fmt_msg, path, err_msg);
        goto out;
    }

    items = fread(secret, sizeof(TPM2B_ENCRYPTED_SECRET), 1, fp);
    if (items != 1) {
        const char *fmt_msg =
                "Reading secret from file \"%s\" failed, error: \"%s\"";
        const char *err_msg = "Unknown error";
        if (ferror(fp)) {
            err_msg = strerror(errno);
        } else if (feof(fp)) {
            err_msg = "end of file";
        }
        LOG_ERR(fmt_msg, path, err_msg);
        goto out;
    }

    result = true;
    out: fclose(fp);

    return result;
}

static bool output_and_save(TPM2B_DIGEST *digest, const char *path) {

    printf("\nCertInfoData :\n");

    unsigned k;
    for (k = 0; k < digest->t.size; k++) {
        printf("0x%.2x ", digest->t.buffer[k]);
    }
    printf("\n\n");

    return files_save_bytes_to_file(path, digest->t.buffer, digest->t.size);
}

static bool activate_credential_and_output(TSS2_SYS_CONTEXT *sapi_context,
        tpm_activatecred_ctx *ctx) {

    TPM2B_DIGEST certInfoData = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMS_AUTH_COMMAND tmp_auth = {
            .nonce = { .t = { .size = 0 } },
            .hmac =  { .t = { .size = 0 } },
            .sessionHandle = 0,
            .sessionAttributes = { .val = 0 },
    };

    ctx->password.sessionHandle = TPM_RS_PW;
    ctx->endorse_password.sessionHandle = TPM_RS_PW;

    TPMS_AUTH_COMMAND *cmd_session_array_password[2] = {
        &ctx->password,
        &tmp_auth
    };

    TSS2_SYS_CMD_AUTHS cmd_auth_array_password = {
        2, &cmd_session_array_password[0]
    };

    TPMS_AUTH_COMMAND *cmd_session_array_endorse[1] = {
        &ctx->endorse_password
    };

    TSS2_SYS_CMD_AUTHS cmd_auth_array_endorse = {
        1, &cmd_session_array_endorse[0]
    };

    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;

    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM_ALG_NULL
    };

    SESSION *session = NULL;
    UINT32 rval = tpm_session_start_auth_with_params(sapi_context, &session,
            TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt,
            TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_start_auth_with_params Error. TPM Error:0x%x",
                rval);
        return false;
    }

    rval = Tss2_Sys_PolicySecret(sapi_context, TPM_RH_ENDORSEMENT,
            session->sessionHandle, &cmd_auth_array_endorse, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return false;
    }

    tmp_auth.sessionHandle = session->sessionHandle;
    tmp_auth.sessionAttributes.continueSession = 1;
    tmp_auth.hmac.t.size = 0;

    rval = Tss2_Sys_ActivateCredential(sapi_context, ctx->handle.activate,
            ctx->handle.key, &cmd_auth_array_password, &ctx->credentialBlob, &ctx->secret,
            &certInfoData, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("ActivateCredential failed. TPM Error:0x%x", rval);
        return false;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(sapi_context, session->sessionHandle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return false;
    }

    tpm_session_auth_end(session);

    return output_and_save(&certInfoData, ctx->file.output);
}

static bool init(int argc, char *argv[], tpm_activatecred_ctx *ctx) {

    static const char *optstring = "H:c:k:C:P:e:f:o:X";
    static const struct option long_options[] = {
        {"handle",        required_argument, NULL, 'H'},
        {"context",       required_argument, NULL, 'c'},
        {"keyHandle",     required_argument, NULL, 'k'},
        {"keyContext",    required_argument, NULL, 'C'},
        {"Password",      required_argument, NULL, 'P'},
        {"endorsePasswd", required_argument, NULL, 'e'},
        {"inFile",        required_argument, NULL, 'f'},
        {"outFile",       required_argument, NULL, 'o'},
        {"passwdInHex",   no_argument,       NULL, 'X'},
        {NULL,            no_argument,       NULL,  '\0'},
    };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int H_flag = 0, c_flag = 0, k_flag = 0, C_flag = 0,
            f_flag = 0, o_flag = 0;

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'H':
            result = tpm2_util_string_to_uint32(optarg, &ctx->handle.activate);
            if (!result) {
                LOG_ERR("Could not convert -H argument to a number, "
                        "got \"%s\"!", optarg);
                return false;
            }
            H_flag = 1;
            break;
        case 'c':
            ctx->file.context = optarg;
            c_flag = 1;
            break;
        case 'k':
            result = tpm2_util_string_to_uint32(optarg, &ctx->handle.key);
            if (!result) {
                return false;
            }
            k_flag = 1;
            break;
        case 'C':
            ctx->file.key_context = optarg;
            C_flag = 1;
            break;
        case 'P':
            result = tpm2_password_util_from_optarg(optarg, &ctx->password.hmac);
            if (!result) {
                LOG_ERR("Invalid handle password, got\"%s\"", optarg);
                return false;
            }
            //P_flag = 1;
            break;
        case 'e':
            result = tpm2_password_util_from_optarg(optarg, &ctx->endorse_password.hmac);
            if (!result) {
                LOG_ERR("Invalid endorse password, got\"%s\"", optarg);
                return false;
            }
            break;
        case 'f':
            /* logs errors */
            result = read_cert_secret(optarg, &ctx->credentialBlob,
                    &ctx->secret);
            if (!result) {
                return false;
            }
            f_flag = 1;
            break;
        case 'o':
            ctx->file.output = optarg;
            o_flag = 1;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??", opt);
            return false;
        }
    };

    if ((!H_flag && !c_flag )
            && (!k_flag || !C_flag) && !f_flag && !o_flag) {
        showArgMismatch(argv[0]);
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused, avoid compiler warning */
    (void) opts;
    (void) envp;

    /*
    * A bug in certain gcc versions prevents us from using = { 0 };
    * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
    *
    * Declare it static since we don't need thread safety.
    */
    static tpm_activatecred_ctx ctx;

    bool result = init(argc, argv, &ctx);
    if (!result) {
        LOG_ERR("Initialization failed");
        return 1;
    }

    if (ctx.file.context) {
        bool res = files_load_tpm_context_from_file(sapi_context, &ctx.handle.activate,
                ctx.file.context);
        if (!res) {
            return 1;
        }
    }

    if (ctx.file.key_context) {
        bool res = files_load_tpm_context_from_file(sapi_context, &ctx.handle.key,
                ctx.file.key_context) != true;
        if (!res) {
            return 1;
        }
    }

    result = activate_credential_and_output(sapi_context, &ctx);
    if (!result) {
        return 1;
    }

    return 0;
}
