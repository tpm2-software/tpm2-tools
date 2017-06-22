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

typedef struct getpubak_context getpubak_context;
struct getpubak_context {
    struct {
        TPM_HANDLE ek;
        TPM_HANDLE ak;
    } persistent_handle;
    struct {
        TPM2B_AUTH endorse;
        TPM2B_AUTH ak;
        TPM2B_AUTH owner;
    } passwords;
    bool hexPasswd;
    char outputFile[PATH_MAX];
    char aknameFile[PATH_MAX];
    UINT32 algorithmType;
    UINT32 digestAlg;
    UINT32 signAlg;
    TSS2_SYS_CONTEXT *sapi_context;
};

/*
 * TODO: All these set_xxx_signing_algorithm() routines could likely somehow be refactored into one.
 */
static bool set_rsa_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg, TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM_ALG_NULL) {
        sign_alg = TPM_ALG_RSASSA;
    }

    in_public->t.publicArea.parameters.rsaDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM_ALG_RSASSA :
    case TPM_ALG_RSAPSS :
        in_public->t.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The RSA signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_ecc_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM_ALG_NULL) {
        sign_alg = TPM_ALG_ECDSA;
    }

    in_public->t.publicArea.parameters.eccDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM_ALG_ECDSA :
    case TPM_ALG_SM2 :
    case TPM_ALG_ECSCHNORR :
    case TPM_ALG_ECDAA :
        in_public->t.publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The ECC signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_keyed_hash_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM_ALG_NULL) {
        sign_alg = TPM_ALG_HMAC;
    }

    in_public->t.publicArea.parameters.keyedHashDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM_ALG_HMAC :
        in_public->t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR(
                "The Keyedhash signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_key_algorithm(getpubak_context *ctx, TPM2B_PUBLIC *in_public)
{
    in_public->t.publicArea.nameAlg = TPM_ALG_SHA256;
    // First clear attributes bit field.
    *(UINT32 *)&(in_public->t.publicArea.objectAttributes) = 0;
    in_public->t.publicArea.objectAttributes.restricted = 1;
    in_public->t.publicArea.objectAttributes.userWithAuth = 1;
    in_public->t.publicArea.objectAttributes.sign = 1;
    in_public->t.publicArea.objectAttributes.decrypt = 0;
    in_public->t.publicArea.objectAttributes.fixedTPM = 1;
    in_public->t.publicArea.objectAttributes.fixedParent = 1;
    in_public->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    in_public->t.publicArea.authPolicy.t.size = 0;

    in_public->t.publicArea.type = ctx->algorithmType;

    switch(ctx->algorithmType)
    {
    case TPM_ALG_RSA:
        in_public->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        in_public->t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        in_public->t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_NULL;
        in_public->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        in_public->t.publicArea.parameters.rsaDetail.exponent = 0;
        in_public->t.publicArea.unique.rsa.t.size = 0;
        return set_rsa_signing_algorithm(ctx->signAlg, ctx->digestAlg, in_public);
    case TPM_ALG_ECC:
        in_public->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        in_public->t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_NULL;
        in_public->t.publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
        in_public->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        in_public->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        in_public->t.publicArea.unique.ecc.x.t.size = 0;
        in_public->t.publicArea.unique.ecc.y.t.size = 0;
        return set_ecc_signing_algorithm(ctx->signAlg, ctx->digestAlg, in_public);
    case TPM_ALG_KEYEDHASH:
        in_public->t.publicArea.unique.keyedHash.t.size = 0;
        return set_keyed_hash_signing_algorithm(ctx->signAlg, ctx->digestAlg, in_public);
    case TPM_ALG_SYMCIPHER:
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx->algorithmType);
        return false;
    }

    return true;
}

static bool create_ak(getpubak_context *ctx) {

    TPML_PCR_SELECTION creation_pcr;
    TPMS_AUTH_COMMAND session_data;
    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    TPM2B_DATA outsideInfo = { { 0, } };
    TPM2B_PUBLIC out_public = {{ 0, } };
    TPM2B_NONCE nonce_caller = { { 0, } };
    TPMT_TK_CREATION creation_ticket = { 0, };
    TPM2B_CREATION_DATA creation_data = { { 0, } };
    TPM2B_ENCRYPTED_SECRET encrypted_salt = { { 0, } };

    TPMT_SYM_DEF symmetric = {
            .algorithm = TPM_ALG_NULL,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);

    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPM_HANDLE handle_2048_rsa = ctx->persistent_handle.ek;

    session_data_array[0] = &session_data;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    session_data.sessionHandle = TPM_RS_PW;
    session_data.nonce.t.size = 0;
    session_data.hmac.t.size = 0;
    *((UINT8 *) ((void *) &session_data.sessionAttributes)) = 0;

    sessions_data.cmdAuthsCount = 1;
    sessions_data_out.rspAuthsCount = 1;
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;
    creation_pcr.count = 0;

    bool result = password_util_to_auth(&ctx->passwords.ak, ctx->hexPasswd, "AK",
            &inSensitive.t.sensitive.userAuth);
    if (!result) {
        return false;
    }

    result = set_key_algorithm(ctx, &inPublic);
    if (!result) {
        return false;
    }

    result = password_util_to_auth(&ctx->passwords.endorse, ctx->hexPasswd,
            "endorse", &session_data.hmac);
    if (!result) {
        return false;
    }

    SESSION *session = NULL;
    UINT32 rval = tpm_session_start_auth_with_params(ctx->sapi_context, &session, TPM_RH_NULL, 0, TPM_RH_NULL, 0,
            &nonce_caller, &encrypted_salt, TPM_SE_POLICY, &symmetric,
            TPM_ALG_SHA256);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_start_auth_with_params Error. TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    rval = Tss2_Sys_PolicySecret(ctx->sapi_context, TPM_RH_ENDORSEMENT,
            session->sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("Tss2_Sys_PolicySecret succ");

    session_data.sessionHandle = session->sessionHandle;
    session_data.sessionAttributes.continueSession = 1;
    session_data.hmac.t.size = 0;

    rval = Tss2_Sys_Create(ctx->sapi_context, handle_2048_rsa, &sessions_data,
            &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
            &out_public, &creation_data, &creation_hash, &creation_ticket,
            &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Create Error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("TPM2_Create succ");

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(ctx->sapi_context, session->sessionHandle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_INFO("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return false;
    }
    // And remove the session from sessions table.
    rval = tpm_session_auth_end(session);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_auth_end Error. TPM Error:0x%x", rval);
        return false;
    }

    session_data.sessionHandle = TPM_RS_PW;
    session_data.sessionAttributes.continueSession = 0;
    session_data.hmac.t.size = 0;

    result = password_util_to_auth(&ctx->passwords.endorse, ctx->hexPasswd,
            "endorse", &session_data.hmac);
    if (!result) {
        return false;
    }

    rval = tpm_session_start_auth_with_params(ctx->sapi_context, &session, TPM_RH_NULL, 0, TPM_RH_NULL, 0,
            &nonce_caller, &encrypted_salt, TPM_SE_POLICY, &symmetric,
            TPM_ALG_SHA256);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_start_auth_with_params Error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("tpm_session_start_auth_with_params succ");

    rval = Tss2_Sys_PolicySecret(ctx->sapi_context, TPM_RH_ENDORSEMENT,
            session->sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("Tss2_Sys_PolicySecret succ");

    session_data.sessionHandle = session->sessionHandle;
    session_data.sessionAttributes.continueSession = 1;
    session_data.hmac.t.size = 0;

    TPM_HANDLE loaded_sha1_key_handle;
    rval = Tss2_Sys_Load(ctx->sapi_context, handle_2048_rsa, &sessions_data, &out_private,
            &out_public, &loaded_sha1_key_handle, &name, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Load Error. TPM Error:0x%x", rval);
        return false;
    }

    /* required output of testing scripts */
    printf("Name of loaded key: ");
    string_bytes_print_tpm2b(&name.b);
    printf("\n");
    printf("Loaded key handle:  %8.8x\n", loaded_sha1_key_handle);

    // write name to ak.name file
    result = files_save_bytes_to_file(ctx->aknameFile, &name.t.name[0], name.t.size);
    if (!result) {
        LOG_ERR("Failed to save AK name into file \"%s\"", ctx->aknameFile);
        return false;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(ctx->sapi_context, session->sessionHandle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return false;
    }

    // And remove the session from sessions table.
    rval = tpm_session_auth_end(session);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_auth_end Error. TPM Error:0x%x", rval);
        return false;
    }

    session_data.sessionHandle = TPM_RS_PW;
    session_data.sessionAttributes.continueSession = 0;
    session_data.hmac.t.size = 0;

    // use the owner auth here.
    result = password_util_to_auth(&ctx->passwords.owner, ctx->hexPasswd, "owner",
            &session_data.hmac);
    if (!result) {
        return false;
    }

    rval = Tss2_Sys_EvictControl(ctx->sapi_context, TPM_RH_OWNER, loaded_sha1_key_handle,
            &sessions_data, ctx->persistent_handle.ak, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("\n......TPM2_EvictControl Error. TPM Error:0x%x......\n",
                rval);
        return false;
    }
    LOG_INFO("EvictControl: Make AK persistent succ.");

    rval = Tss2_Sys_FlushContext(ctx->sapi_context, loaded_sha1_key_handle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Flush transient AK error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("Flush transient AK succ.");

    /* TODO fix this serialization */
    result = files_save_bytes_to_file(ctx->outputFile, (UINT8 *) &out_public, sizeof(out_public));
    if (!result) {
        LOG_ERR("Failed to save AK pub key into file \"%s\"", ctx->outputFile);
        return false;
    }

    return true;
}

static bool init(int argc, char *argv[], getpubak_context *ctx) {

    struct option opts[] =
    {
        { "ownerPasswd", required_argument, NULL, 'o' },
        { "endorsePasswd", required_argument, NULL, 'e' },
        { "ekHandle"   , required_argument, NULL, 'E' },
        { "akHandle"   , required_argument, NULL, 'k' },
        { "alg"        , required_argument, NULL, 'g' },
        { "digestAlg"  , required_argument, NULL, 'D' },
        { "signAlg"    , required_argument, NULL, 's' },
        { "akPasswd"   , required_argument, NULL, 'P' },
        { "file"       , required_argument, NULL, 'f' },
        { "akName"     , required_argument, NULL, 'n' },
        { "passwdInHex", no_argument,       NULL, 'X' },
        { NULL         , no_argument,       NULL,  0  },
    };

    if (argc == 1 || argc > (int) (2 * sizeof(opts) / sizeof(opts[0]))) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    bool result;

    optind = 0;
    while ((opt = getopt_long(argc, argv, "o:E:e:k:g:D:s:P:f:n:Xp:", opts, NULL))
            != -1) {
        switch (opt) {
        case 'E':
            result = string_bytes_get_uint32(optarg, &ctx->persistent_handle.ek);
            if (!result) {
                LOG_ERR("Could not convert persistent EK handle.");
                return false;
            }
            break;
        case 'k':
            result = string_bytes_get_uint32(optarg, &ctx->persistent_handle.ak);
            if (!result) {
                LOG_ERR("Could not convert persistent AK handle.");
                return false;
            }
            break;
        case 'g':
            result = string_bytes_get_uint32(optarg, &ctx->algorithmType);
            if (!result) {
                LOG_ERR("Could not convert algorithm.");
                return false;
            }
            break;
        case 'D':
            result = string_bytes_get_uint32(optarg, &ctx->digestAlg);
            if (!result) {
                LOG_ERR("Could not convert digest algorithm.");
                return false;
            }
            break;
        case 's':
            result = string_bytes_get_uint32(optarg, &ctx->signAlg);
            if (!result) {
                LOG_ERR("Could not convert signing algorithm.");
                return false;
            }
            break;
        case 'o':
            result = password_util_copy_password(optarg, "owner",
                    &ctx->passwords.owner);
            if (!result) {
                return false;
            }
            break;
        case 'e':
            result = password_util_copy_password(optarg, "endorse",
                    &ctx->passwords.endorse);
            if (!result) {
                return false;
            }
            break;
        case 'P':
            result = password_util_copy_password(optarg, "AK", &ctx->passwords.ak);
            if (!result) {
                return false;
            }
            break;
        case 'f':
            if (!optarg) {
                LOG_ERR(
                        "Please specify the output file used to save the pub ek.");
                return false;
            }
            snprintf(ctx->outputFile, sizeof(ctx->outputFile), "%s", optarg);
            break;
        case 'n':
            if (!optarg) {
                LOG_ERR(
                        "Please specify the output file used to save the ak name.");
                return false;
            }
            snprintf(ctx->aknameFile, sizeof(ctx->aknameFile), "%s", optarg);
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
    }
    return true;
}

ENTRY_POINT(getpubak) {

    /* opts is unused, avoid compiler warning */
    (void)opts;
    (void)envp;

    getpubak_context ctx = {
            .hexPasswd = false,
            .algorithmType = TPM_ALG_RSA,
            .digestAlg = TPM_ALG_SHA256,
            .signAlg = TPM_ALG_NULL,
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return !create_ak(&ctx);
}
