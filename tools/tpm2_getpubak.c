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

#include <sapi/tpm20.h>

#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "files.h"
#include "log.h"
#include "tpm2_util.h"
#include "tpm_session.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

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
    char *output_file;
    char *akname_file;
    TPM_ALG_ID algorithm_type;
    TPM_ALG_ID digest_alg;
    TPM_ALG_ID sign_alg;
};

static getpubak_context ctx = {
    .algorithm_type = TPM_ALG_RSA,
    .digest_alg = TPM_ALG_SHA256,
    .sign_alg = TPM_ALG_NULL,
    .passwords = {
        .endorse = TPM2B_EMPTY_INIT,
        .ak      = TPM2B_EMPTY_INIT,
        .owner   = TPM2B_EMPTY_INIT,
    },
};

/*
 * TODO: All these set_xxx_signing_algorithm() routines could likely somehow be refactored into one.
 */
static bool set_rsa_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg, TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM_ALG_NULL) {
        sign_alg = TPM_ALG_RSASSA;
    }

    in_public->publicArea.parameters.rsaDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM_ALG_RSASSA :
    case TPM_ALG_RSAPSS :
        in_public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
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

    in_public->publicArea.parameters.eccDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM_ALG_ECDSA :
    case TPM_ALG_SM2 :
    case TPM_ALG_ECSCHNORR :
    case TPM_ALG_ECDAA :
        in_public->publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg =
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

    in_public->publicArea.parameters.keyedHashDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM_ALG_HMAC :
        in_public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
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

static bool set_key_algorithm(TPM2B_PUBLIC *in_public)
{
    in_public->publicArea.nameAlg = TPM_ALG_SHA256;
    // First clear attributes bit field.
    *(UINT32 *)&(in_public->publicArea.objectAttributes) = 0;
    in_public->publicArea.objectAttributes.restricted = 1;
    in_public->publicArea.objectAttributes.userWithAuth = 1;
    in_public->publicArea.objectAttributes.sign = 1;
    in_public->publicArea.objectAttributes.decrypt = 0;
    in_public->publicArea.objectAttributes.fixedTPM = 1;
    in_public->publicArea.objectAttributes.fixedParent = 1;
    in_public->publicArea.objectAttributes.sensitiveDataOrigin = 1;
    in_public->publicArea.authPolicy.size = 0;

    in_public->publicArea.type = ctx.algorithm_type;

    switch(ctx.algorithm_type)
    {
    case TPM_ALG_RSA:
        in_public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        in_public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.keyBits = 2048;
        in_public->publicArea.parameters.rsaDetail.exponent = 0;
        in_public->publicArea.unique.rsa.size = 0;
        return set_rsa_signing_algorithm(ctx.sign_alg, ctx.digest_alg, in_public);
    case TPM_ALG_ECC:
        in_public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
        in_public->publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        in_public->publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        in_public->publicArea.unique.ecc.x.size = 0;
        in_public->publicArea.unique.ecc.y.size = 0;
        return set_ecc_signing_algorithm(ctx.sign_alg, ctx.digest_alg, in_public);
    case TPM_ALG_KEYEDHASH:
        in_public->publicArea.unique.keyedHash.size = 0;
        return set_keyed_hash_signing_algorithm(ctx.sign_alg, ctx.digest_alg, in_public);
    case TPM_ALG_SYMCIPHER:
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx.algorithm_type);
        return false;
    }

    return true;
}

static bool create_ak(TSS2_SYS_CONTEXT *sapi_context) {

    TPML_PCR_SELECTION creation_pcr;
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    };
    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;
    TPM2B_NONCE nonce_caller = TPM2B_EMPTY_INIT;
    TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
    TPM2B_CREATION_DATA creation_data = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET encrypted_salt = TPM2B_EMPTY_INIT;

    TPMT_SYM_DEF symmetric = {
            .algorithm = TPM_ALG_NULL,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);

    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPM_HANDLE handle_2048_rsa = ctx.persistent_handle.ek;

    session_data_array[0] = &session_data;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data.cmdAuthsCount = 1;
    sessions_data_out.rspAuthsCount = 1;
    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;
    creation_pcr.count = 0;

    memcpy(&inSensitive.sensitive.userAuth, &ctx.passwords.ak, sizeof(ctx.passwords.ak));

    bool result = set_key_algorithm(&inPublic);
    if (!result) {
        return false;
    }

    memcpy(&session_data.hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

    SESSION *session = NULL;
    UINT32 rval = tpm_session_start_auth_with_params(sapi_context, &session, TPM_RH_NULL, 0, TPM_RH_NULL, 0,
            &nonce_caller, &encrypted_salt, TPM_SE_POLICY, &symmetric,
            TPM_ALG_SHA256);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_start_auth_with_params Error. TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM_RH_ENDORSEMENT,
            session->sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("Tss2_Sys_PolicySecret succ");

    session_data.sessionHandle = session->sessionHandle;
    session_data.sessionAttributes.continueSession = 1;
    session_data.hmac.size = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, handle_2048_rsa, &sessions_data,
            &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
            &out_public, &creation_data, &creation_hash, &creation_ticket,
            &sessions_data_out));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Create Error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("TPM2_Create succ");

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, session->sessionHandle));
    if (rval != TPM_RC_SUCCESS) {
        LOG_INFO("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return false;
    }
    // And remove the session from sessions table.
    tpm_session_auth_end(session);

    session_data.sessionHandle = TPM_RS_PW;
    session_data.sessionAttributes.continueSession = 0;
    session_data.hmac.size = 0;

    memcpy(&session_data.hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

    rval = tpm_session_start_auth_with_params(sapi_context, &session, TPM_RH_NULL, 0, TPM_RH_NULL, 0,
            &nonce_caller, &encrypted_salt, TPM_SE_POLICY, &symmetric,
            TPM_ALG_SHA256);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("tpm_session_start_auth_with_params Error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("tpm_session_start_auth_with_params succ");

    rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM_RH_ENDORSEMENT,
            session->sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("Tss2_Sys_PolicySecret succ");

    session_data.sessionHandle = session->sessionHandle;
    session_data.sessionAttributes.continueSession = 1;
    session_data.hmac.size = 0;

    TPM_HANDLE loaded_sha1_key_handle;
    rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sapi_context, handle_2048_rsa, &sessions_data, &out_private,
            &out_public, &loaded_sha1_key_handle, &name, &sessions_data_out));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Load Error. TPM Error:0x%x", rval);
        return false;
    }

    /* required output of testing scripts */
    tpm2_tool_output("Name of loaded key: ");
    tpm2_util_print_tpm2b((TPM2B *)&name);
    tpm2_tool_output("\n");
    tpm2_tool_output("Loaded key handle:  %8.8x\n", loaded_sha1_key_handle);

    // write name to ak.name file
    result = files_save_bytes_to_file(ctx.akname_file, &name.name[0], name.size);
    if (!result) {
        LOG_ERR("Failed to save AK name into file \"%s\"", ctx.akname_file);
        return false;
    }

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, session->sessionHandle));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return false;
    }

    // And remove the session from sessions table.
    tpm_session_auth_end(session);

    session_data.sessionHandle = TPM_RS_PW;
    session_data.sessionAttributes.continueSession = 0;
    session_data.hmac.size = 0;

    // use the owner auth here.
    memcpy(&session_data.hmac, &ctx.passwords.owner, sizeof(ctx.passwords.owner));

    rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, TPM_RH_OWNER, loaded_sha1_key_handle,
            &sessions_data, ctx.persistent_handle.ak, &sessions_data_out));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("\n......TPM2_EvictControl Error. TPM Error:0x%x......",
                rval);
        return false;
    }
    LOG_INFO("EvictControl: Make AK persistent succ.");

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, loaded_sha1_key_handle));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Flush transient AK error. TPM Error:0x%x", rval);
        return false;
    }
    LOG_INFO("Flush transient AK succ.");

    /* TODO fix this serialization */
    result = files_save_bytes_to_file(ctx.output_file, (UINT8 *) &out_public, sizeof(out_public));
    if (!result) {
        LOG_ERR("Failed to save AK pub key into file \"%s\"", ctx.output_file);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'E':
        result = tpm2_util_string_to_uint32(value, &ctx.persistent_handle.ek);
        if (!result) {
            LOG_ERR("Could not convert persistent EK handle.");
            return false;
        }
        break;
    case 'k':
        result = tpm2_util_string_to_uint32(value, &ctx.persistent_handle.ak);
        if (!result) {
            LOG_ERR("Could not convert persistent AK handle.");
            return false;
        }
        break;
    case 'g':
        ctx.algorithm_type = tpm2_alg_util_from_optarg(value);
        if (ctx.algorithm_type == TPM_ALG_ERROR) {
            LOG_ERR("Could not convert algorithm. got: \"%s\".", value);
            return false;
        }
        break;
    case 'D':
        ctx.digest_alg = tpm2_alg_util_from_optarg(value);
        if (ctx.digest_alg == TPM_ALG_ERROR) {
            LOG_ERR("Could not convert digest algorithm.");
            return false;
        }
        break;
    case 's':
        ctx.sign_alg = tpm2_alg_util_from_optarg(value);
        if (ctx.sign_alg == TPM_ALG_ERROR) {
            LOG_ERR("Could not convert signing algorithm.");
            return false;
        }
        break;
    case 'o':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.owner);
        if (!result) {
            LOG_ERR("Invalid owner password, got\"%s\"", value);
            return false;
        }
        break;
    case 'e':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.endorse);
        if (!result) {
            LOG_ERR("Invalid endorse password, got\"%s\"", value);
            return false;
        }
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.ak);
        if (!result) {
            LOG_ERR("Invalid AK password, got\"%s\"", value);
            return false;
        }
        break;
    case 'f':
        if (!value) {
            LOG_ERR("Please specify the output file used to save the pub ek.");
            return false;
        }
        ctx.output_file = value;
        break;
    case 'n':
        if (!value) {
            LOG_ERR("Please specify the output file used to save the ak name.");
            return false;
        }
        ctx.akname_file = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "owner-passwd", required_argument, NULL, 'o' },
        { "endorse-passwd", required_argument, NULL, 'e' },
        { "ek-handle"   , required_argument, NULL, 'E' },
        { "ak-handle"   , required_argument, NULL, 'k' },
        { "alg"        , required_argument, NULL, 'g' },
        { "digest-alg"  , required_argument, NULL, 'D' },
        { "sign-alg"    , required_argument, NULL, 's' },
        { "ak-passwd"   , required_argument, NULL, 'P' },
        { "file"       , required_argument, NULL, 'f' },
        { "ak-name"     , required_argument, NULL, 'n' },
    };

    *opts = tpm2_options_new("o:E:e:k:g:D:s:P:f:n:p:", ARRAY_LEN(topts), topts, on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    return !create_ak(sapi_context);
}
