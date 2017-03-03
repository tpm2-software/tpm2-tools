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

#include <getopt.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "password_util.h"
#include "string-bytes.h"

typedef struct getpubek_context getpubek_context;
struct getpubek_context {
    struct {
        bool is_hex;
        TPM2B_AUTH owner;
        TPM2B_AUTH endorse;
        TPM2B_AUTH ek;
    } passwords;
    char out_file_path[PATH_MAX];
    TPM_HANDLE persistent_handle;
    UINT32 algorithm;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool set_key_algorithm(UINT16 algorithm, TPM2B_PUBLIC *inPublic)
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

    inPublic->t.publicArea.type = algorithm;

    switch (algorithm) {
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
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", algorithm);
        return false;
    }

    return true;
}

static bool create_ek_handle(getpubek_context *ctx) {

    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TPML_PCR_SELECTION creationPCR;

    TPM2B_SENSITIVE_CREATE inSensitive =
            TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);

    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

    TPM2B_DATA outsideInfo = {
            { 0, }
    };

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_PUBLIC outPublic = {
            { 0, }
    };

    TPM2B_CREATION_DATA creationData = {
            { 0, }
    };

    TPM2B_DIGEST creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPMT_TK_CREATION creationTicket = { 0, };

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *) ((void *) &sessionData.sessionAttributes)) = 0;

    bool result = password_util_to_auth(&ctx->passwords.endorse,
            ctx->passwords.is_hex, "endorse", &sessionData.hmac);
    if (!result) {
        return false;
    }

    result = password_util_to_auth(&ctx->passwords.ek, ctx->passwords.is_hex,
            "ek", &inSensitive.t.sensitive.userAuth);
    if (!result) {
        return false;
    }

    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;

    result = set_key_algorithm(ctx->algorithm, &inPublic);
    if (!result) {
        return false;
    }

    creationPCR.count = 0;

    /* Create EK and get a handle to the key */
    TPM_HANDLE handle2048ek;
    UINT32 rval = Tss2_Sys_CreatePrimary(ctx->sapi_context, TPM_RH_ENDORSEMENT,
            &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
            &handle2048ek, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_CreatePrimary Error. TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("EK create success. Got handle: 0x%8.8x", handle2048ek);

    // To make EK persistent, use own auth
    sessionData.hmac.t.size = 0;
    result = password_util_to_auth(&ctx->passwords.owner, ctx->passwords.is_hex,
            "owner", &sessionData.hmac);
    if (!result) {
        return false;
    }

    rval = Tss2_Sys_EvictControl(ctx->sapi_context, TPM_RH_OWNER, handle2048ek,
            &sessionsData, ctx->persistent_handle, &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("EvictControl failed. Could not make EK persistent."
                "TPM Error:0x%x", rval);
        return false;
    }

    LOG_INFO("EvictControl EK persistent success.");

    rval = Tss2_Sys_FlushContext(ctx->sapi_context, handle2048ek);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Flush transient EK failed. TPM Error:0x%x",
                rval);
        return false;
    }

    LOG_INFO("Flush transient EK success.");

    /* TODO fix this serialization */
    if (!files_save_bytes_to_file(ctx->out_file_path, (UINT8 *) &outPublic,
            sizeof(outPublic))) {
        LOG_ERR("Failed to save EK pub key into file \"%s\"",
                ctx->out_file_path);
        return false;
    }

    return true;
}

static bool init(int argc, char *argv[], char *envp[], getpubek_context *ctx) {

    struct option options[] =
    {
        { "endorsePasswd", required_argument, NULL, 'e' },
        { "ownerPasswd"  , required_argument, NULL, 'o' },
        { "handle"       , required_argument, NULL, 'H' },
        { "ekPasswd"     , required_argument, NULL, 'P' },
        { "alg"          , required_argument, NULL, 'g' },
        { "file"         , required_argument, NULL, 'f' },
        { "passwdInHex"  , no_argument,       NULL, 'X' },
        { "dbg"          , required_argument, NULL, 'd' },
        { "help"         , no_argument,       NULL, 'h' },
        { NULL           , no_argument,       NULL,  '\0' },
    };

    if (argc == 1) {
        execute_man(argv[0], envp);
        return 1;
    }

    if (argc > (int) (2 * sizeof(options) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return -1;
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "e:o:H:P:g:f:Xp:d:hv", options, NULL))
            != -1) {
        bool result;
        switch (opt) {
        case 'H':
            result = string_bytes_get_uint32(optarg, &ctx->persistent_handle);
            if (!result) {
                LOG_ERR("Could not convert EK persistent from hex format.\n");
                return false;
            }
            break;

        case 'e':
            result = password_util_copy_password(optarg, "endorsement password",
                    &ctx->passwords.endorse);
            if (!result) {
                return false;
            }
            break;
        case 'o':
            result = password_util_copy_password(optarg, "owner password",
                    &ctx->passwords.owner);
            if (!result) {
                return false;
            }
            break;
        case 'P':
            result = password_util_copy_password(optarg, "EK password", &ctx->passwords.ek);
            if (!result) {
                return false;
            }
            break;
        case 'g':
            result = string_bytes_get_uint32(optarg, &ctx->algorithm);
            if (!result) {
                LOG_ERR("Could not convert algorithm to value, got: %s",
                        optarg);
                return false;
            }
            break;
        case 'f':
            if (!optarg) {
                LOG_ERR("Please specify an output file to save the pub ek to.");
                return false;
            }
            snprintf(ctx->out_file_path, sizeof(ctx->out_file_path), "%s",
                    optarg);
            break;
        case 'X':
            ctx->passwords.is_hex = true;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
        }

    }
    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* common options are not used, avoid compiler warning */
    (void) opts;

    getpubek_context ctx = {
            .passwords = { 0 },
            .algorithm = TPM_ALG_RSA,
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, envp, &ctx);
    if (!result) {
        return false;
    }

    /* normalize 0 success 1 failure */
    return create_ek_handle(&ctx) != true;
}
