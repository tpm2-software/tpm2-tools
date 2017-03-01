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

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "password_util.h"
#include "string-bytes.h"
#include "tpm_session.h"

typedef struct tpm_activatecred_ctx tpm_activatecred_ctx;
struct tpm_activatecred_ctx {

    struct {
        TPMI_DH_OBJECT activate;
        TPMI_DH_OBJECT key;
    } handle;

    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
    bool hexPasswd;

    TPMS_AUTH_COMMAND password;
    TPMS_AUTH_COMMAND endorse_password;

    struct {
        char output[PATH_MAX];
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

    TPM2B_DIGEST certInfoData = { { sizeof(certInfoData) - 2, } };
    TPMS_AUTH_COMMAND tmp_auth;

    ctx->password.sessionHandle = TPM_RS_PW;
    ctx->endorse_password.sessionHandle = TPM_RS_PW;
    *((UINT8 *) ((void *) &ctx->password.sessionAttributes)) = 0;
    *((UINT8 *) ((void *) &ctx->endorse_password.sessionAttributes)) = 0;
    *((UINT8 *) ((void *) &tmp_auth.sessionAttributes)) = 0;

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

    TPM2B_ENCRYPTED_SECRET encryptedSalt = {
        { 0, }
    };

    TPM2B_NONCE nonceCaller = {
        { 0, }
    };

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM_ALG_NULL
    };

    bool result = password_util_to_auth(&ctx->password.hmac, ctx->hexPasswd,
            "handlePasswd", &ctx->password.hmac);
    if (!result) {
        return false;
    }

    result = password_util_to_auth(&ctx->endorse_password.hmac, ctx->hexPasswd,
            "endorsePasswd", &ctx->endorse_password.hmac);
    if (!result) {
        return false;
    }

    SESSION *session;
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

    // And remove the session from sessions table.
    rval = tpm_session_auth_end(session);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("EndAuthSession Error. TPM Error:0x%x", rval);
        return false;
    }

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

    int flag_cnt = 0;
    int H_flag = 0, c_flag = 0, k_flag = 0, C_flag = 0, e_flag = 0, P_flag = 0,
            f_flag = 0, o_flag = 0;

    int opt;
    int rc;
    bool result;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'H':
            result = string_bytes_get_uint32(optarg, &ctx->handle.activate);
            if (!result) {
                LOG_ERR("Could not convert -H argument to a number, "
                        "got \"%s\"!", optarg);
                return false;
            }
            H_flag = 1;
            break;
        case 'c':
            ctx->file.context = strdup(optarg);
            if (!ctx->file.context) {
                LOG_ERR("oom");
                return false;
            }
            c_flag = 1;
            break;
        case 'k':
            result = string_bytes_get_uint32(optarg, &ctx->handle.key);
            if (!result) {
                return false;
            }
            k_flag = 1;
            break;
        case 'C':
            ctx->file.key_context = strdup(optarg);
            if (!ctx->file.key_context) {
                LOG_ERR("oom");
                return false;
            }
            C_flag = 1;
            break;
        case 'P':
            ctx->password.hmac.t.size = sizeof(ctx->password.hmac.t) - 2;
            rc = str2ByteStructure(optarg, &ctx->password.hmac.t.size,
                    ctx->password.hmac.t.buffer);
            if (rc) {
                LOG_ERR("Could not convert password \"%s\" into byte array",
                        optarg);
                return false;
            }
            P_flag = 1;
            break;
        case 'e':
            ctx->endorse_password.hmac.t.size =
                    sizeof(ctx->endorse_password.hmac.t) - 2;
            rc = str2ByteStructure(optarg, &ctx->endorse_password.hmac.t.size,
                    ctx->endorse_password.hmac.t.buffer);
            if (rc) {
                LOG_ERR(
                        "Could not convert endorsePassword \"%s\" into byte array",
                        optarg);
                return false;
            }
            e_flag = 1;
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
            snprintf(ctx->file.output, sizeof(ctx->file.output), "%s", optarg);
            o_flag = 1;
            break;
        case 'X':
            ctx->hexPasswd = true;
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
    };

    if ((flag_cnt == 4) && (H_flag == 1 || c_flag == 1)
            && (k_flag == 1 || C_flag == 1) && (f_flag == 1) && (o_flag == 1)) {
        showArgMismatch(argv[0]);
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused, avoid compiler warning */
    (void) opts;

    tpm_activatecred_ctx ctx = { 0 };

    int rc = 1;
    bool result = init(argc, argv, &ctx);
    if (!result) {
        LOG_ERR("Initialization failed\n");
        goto out;
    }

    int returnVal;

    if (ctx.file.context)
        returnVal = file_load_tpm_context_from_file(sapi_context, &ctx.handle.activate,
                ctx.file.context);
    if (returnVal != 0) {
        goto out;
    }

    if (ctx.file.key_context)
        returnVal = file_load_tpm_context_from_file(sapi_context, &ctx.handle.key,
                ctx.file.key_context) != true;
    if (returnVal != 0) {
        goto out;
    }

    result = activate_credential_and_output(sapi_context, &ctx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    free(ctx.file.key_context);
    free(ctx.file.context);
    return rc;
}
