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
#include <limits.h>

#include <sapi/tpm20.h>

#include "tpm2_password_util.h"
#include "files.h"
#include "log.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

typedef struct getpubek_context getpubek_context;
struct getpubek_context {
    struct {
        TPM2B_AUTH owner;
        TPM2B_AUTH endorse;
        TPM2B_AUTH ek;
    } passwords;
    char *out_file_path;
    TPM_HANDLE persistent_handle;
    TPM_ALG_ID algorithm;
    bool is_session_based_auth;
    TPMI_SH_AUTH_SESSION auth_session_handle;
};

static getpubek_context ctx = {
    .passwords = {
        .owner = TPM2B_EMPTY_INIT,
        .endorse = TPM2B_EMPTY_INIT,
        .ek = TPM2B_EMPTY_INIT,
    },
    .algorithm = TPM_ALG_RSA,
    .is_session_based_auth = false
};

static bool set_key_algorithm(TPM2B_PUBLIC *inPublic)
{

    static BYTE auth_policy[] = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
    };

    inPublic->t.publicArea.nameAlg = TPM_ALG_SHA256;

    // First clear attributes bit field.
    *(UINT32 *) &(inPublic->t.publicArea.objectAttributes) = 0;
    inPublic->t.publicArea.objectAttributes.restricted = 1;
    inPublic->t.publicArea.objectAttributes.userWithAuth = 0;
    inPublic->t.publicArea.objectAttributes.adminWithPolicy = 1;
    inPublic->t.publicArea.objectAttributes.sign = 0;
    inPublic->t.publicArea.objectAttributes.decrypt = 1;
    inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic->t.publicArea.objectAttributes.fixedParent = 1;
    inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic->t.publicArea.authPolicy.t.size = 32;
    memcpy(inPublic->t.publicArea.authPolicy.t.buffer, auth_policy, 32);

    inPublic->t.publicArea.type = ctx.algorithm;

    switch (ctx.algorithm) {
    case TPM_ALG_RSA :
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM_ALG_AES;
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.mode.aes =
                TPM_ALG_CFB;
        inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->t.publicArea.unique.rsa.t.size = 256;
        break;
    case TPM_ALG_KEYEDHASH :
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme =
                TPM_ALG_XOR;
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg =
                TPM_ALG_SHA256;
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf =
                TPM_ALG_KDF1_SP800_108;
        inPublic->t.publicArea.unique.keyedHash.t.size = 0;
        break;
    case TPM_ALG_ECC :
        inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm =
                TPM_ALG_AES;
        inPublic->t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.eccDetail.symmetric.mode.sym =
                TPM_ALG_CFB;
        inPublic->t.publicArea.parameters.eccDetail.scheme.scheme =
                TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.unique.ecc.x.t.size = 32;
        inPublic->t.publicArea.unique.ecc.y.t.size = 32;
        break;
    case TPM_ALG_SYMCIPHER :
        inPublic->t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.symDetail.sym.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        inPublic->t.publicArea.unique.sym.t.size = 0;
        break;
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx.algorithm);
        return false;
    }

    return true;
}

static bool create_ek_handle(TSS2_SYS_CONTEXT *sapi_context) {

    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    };

    if (ctx.is_session_based_auth) {
        sessionData.sessionHandle = ctx.auth_session_handle;
    }

    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TPML_PCR_SELECTION creationPCR;

    TPM2B_SENSITIVE_CREATE inSensitive =
            TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);

    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_PUBLIC outPublic = TPM2B_EMPTY_INIT;

    TPM2B_CREATION_DATA creationData = TPM2B_EMPTY_INIT;

    TPM2B_DIGEST creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPMT_TK_CREATION creationTicket = TPMT_TK_CREATION_EMPTY_INIT;

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    memcpy(&sessionData.hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

    memcpy(&ctx.passwords.ek, &inSensitive.t.sensitive.userAuth, sizeof(inSensitive.t.sensitive.userAuth));

    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;

    bool result = set_key_algorithm(&inPublic);
    if (!result) {
        return false;
    }

    creationPCR.count = 0;

    /* Create EK and get a handle to the key */
    TPM_HANDLE handle2048ek;
    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_CreatePrimary(sapi_context, TPM_RH_ENDORSEMENT,
            &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
            &handle2048ek, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_CreatePrimary Error. TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("EK create success. Got handle: 0x%8.8x", handle2048ek);

    memcpy(&sessionData.hmac, &ctx.passwords.owner, sizeof(ctx.passwords.owner));

    rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, TPM_RH_OWNER, handle2048ek,
            &sessionsData, ctx.persistent_handle, &sessionsDataOut));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("EvictControl failed. Could not make EK persistent."
                "TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("EvictControl EK persistent success.");

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle2048ek));
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Flush transient EK failed. TPM Error:0x%x",
                rval);
        return false;
    }

    LOG_INFO("Flush transient EK success.");

    /* TODO fix this serialization */
    if (!files_save_bytes_to_file(ctx.out_file_path, (UINT8 *) &outPublic,
            sizeof(outPublic))) {
        LOG_ERR("Failed to save EK pub key into file \"%s\"",
                ctx.out_file_path);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'H':
        result = tpm2_util_string_to_uint32(value, &ctx.persistent_handle);
        if (!result) {
            LOG_ERR("Could not convert EK persistent from hex format.");
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
    case 'o':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.owner);
        if (!result) {
            LOG_ERR("Invalid owner password, got\"%s\"", value);
            return false;
        }
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.passwords.ek);
        if (!result) {
            LOG_ERR("Invalid EK password, got\"%s\"", value);
            return false;
        }
        break;
    case 'g':
        ctx.algorithm = tpm2_alg_util_from_optarg(value);
        if (ctx.algorithm == TPM_ALG_ERROR) {
            LOG_ERR("Could not convert algorithm to value, got: %s",
                    value);
            return false;
        }
        break;
    case 'f':
        if (!value) {
            LOG_ERR("Please specify an output file to save the pub ek to.");
            return false;
        }
        ctx.out_file_path = value;
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.auth_session_handle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.is_session_based_auth = true;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "endorse-passwd", required_argument, NULL, 'e' },
        { "owner-passwd"  , required_argument, NULL, 'o' },
        { "handle"       , required_argument, NULL, 'H' },
        { "ek-passwd"     , required_argument, NULL, 'P' },
        { "alg"          , required_argument, NULL, 'g' },
        { "file"         , required_argument, NULL, 'f' },
        {"input-session-handle",1,            NULL, 'S' },
        { "dbg"          , required_argument, NULL, 'd' },
        { "help"         , no_argument,       NULL, 'h' },
    };

    *opts = tpm2_options_new("e:o:H:P:g:f:p:S:d:hv", ARRAY_LEN(topts), topts, on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    /* normalize 0 success 1 failure */
    return create_ek_handle(sapi_context) != true;
}
