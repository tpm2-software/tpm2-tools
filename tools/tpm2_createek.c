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
#include <limits.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_password_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct createek_context createek_context;
struct createek_context {
    struct {
        TPM2B_AUTH owner;
        TPM2B_AUTH endorse;
        TPM2B_AUTH ek;
    } passwords;
    char *out_file_path;
    TPM2_HANDLE persistent_handle;
    TPM2_ALG_ID algorithm;
    bool is_session_based_auth;
    TPMI_SH_AUTH_SESSION auth_session_handle;
    tpm2_convert_pubkey_fmt format;
    struct {
        bool f;
    } flags;
};

static createek_context ctx = {
    .passwords = {
        .owner = TPM2B_EMPTY_INIT,
        .endorse = TPM2B_EMPTY_INIT,
        .ek = TPM2B_EMPTY_INIT,
    },
    .algorithm = TPM2_ALG_RSA,
    .is_session_based_auth = false,
    .format = pubkey_format_tss
};

static bool set_key_algorithm(TPM2B_PUBLIC *inPublic)
{

    static BYTE auth_policy[] = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
    };

    inPublic->publicArea.nameAlg = TPM2_ALG_SHA256;

    // First clear attributes bit field.
    inPublic->publicArea.objectAttributes = 0;
    inPublic->publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    inPublic->publicArea.objectAttributes &= ~TPMA_OBJECT_USERWITHAUTH;
    inPublic->publicArea.objectAttributes |= TPMA_OBJECT_ADMINWITHPOLICY;
    inPublic->publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN;
    inPublic->publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    inPublic->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    inPublic->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    inPublic->publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    inPublic->publicArea.authPolicy.size = 32;
    memcpy(inPublic->publicArea.authPolicy.buffer, auth_policy, 32);

    inPublic->publicArea.type = ctx.algorithm;

    switch (ctx.algorithm) {
    case TPM2_ALG_RSA :
        inPublic->publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_AES;
        inPublic->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPublic->publicArea.parameters.rsaDetail.symmetric.mode.aes =
                TPM2_ALG_CFB;
        inPublic->publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_NULL;
        inPublic->publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->publicArea.unique.rsa.size = 256;
        break;
    case TPM2_ALG_KEYEDHASH :
        inPublic->publicArea.parameters.keyedHashDetail.scheme.scheme =
                TPM2_ALG_XOR;
        inPublic->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg =
                TPM2_ALG_SHA256;
        inPublic->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf =
                TPM2_ALG_KDF1_SP800_108;
        inPublic->publicArea.unique.keyedHash.size = 0;
        break;
    case TPM2_ALG_ECC :
        inPublic->publicArea.parameters.eccDetail.symmetric.algorithm =
                TPM2_ALG_AES;
        inPublic->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        inPublic->publicArea.parameters.eccDetail.symmetric.mode.sym =
                TPM2_ALG_CFB;
        inPublic->publicArea.parameters.eccDetail.scheme.scheme =
                TPM2_ALG_NULL;
        inPublic->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        inPublic->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        inPublic->publicArea.unique.ecc.x.size = 32;
        inPublic->publicArea.unique.ecc.y.size = 32;
        break;
    case TPM2_ALG_SYMCIPHER :
        inPublic->publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
        inPublic->publicArea.parameters.symDetail.sym.keyBits.aes = 128;
        inPublic->publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
        inPublic->publicArea.unique.sym.size = 0;
        break;
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx.algorithm);
        return false;
    }

    return true;
}

static bool create_ek_handle(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { 1, {{
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    }}};

    if (ctx.is_session_based_auth) {
        sessionsData.auths[0].sessionHandle = ctx.auth_session_handle;
    }

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

    memcpy(&sessionsData.auths[0].hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

    memcpy(&ctx.passwords.ek, &inSensitive.sensitive.userAuth, sizeof(inSensitive.sensitive.userAuth));

    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;

    bool result = set_key_algorithm(&inPublic);
    if (!result) {
        return false;
    }

    creationPCR.count = 0;

    /* Create EK and get a handle to the key */
    TPM2_HANDLE handle2048ek;
    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_CreatePrimary(sapi_context, TPM2_RH_ENDORSEMENT,
            &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
            &handle2048ek, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_CreatePrimary, rval);
        return false;
    }

    LOG_INFO("EK create success. Got handle: 0x%8.8x", handle2048ek);

    memcpy(&sessionsData.auths[0].hmac, &ctx.passwords.owner, sizeof(ctx.passwords.owner));

    rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, TPM2_RH_OWNER, handle2048ek,
            &sessionsData, ctx.persistent_handle, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_EvictControl, rval);
        return false;
    }

    LOG_INFO("EvictControl EK persistent success.");

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle2048ek));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }

    LOG_INFO("Flush transient EK success.");

    if (ctx.out_file_path) {
        return tpm2_convert_pubkey_save(&outPublic, ctx.format, ctx.out_file_path);
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
        if (ctx.algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert algorithm to value, got: %s",
                    value);
            return false;
        }
        break;
    case 'p':
        if (!value) {
            LOG_ERR("Please specify an output file to save the pub ek to.");
            return false;
        }
        ctx.out_file_path = value;
        break;
    case 'S': {
        tpm2_session *s = tpm2_session_restore(value);
        if (!s) {
            return false;
        }

        ctx.auth_session_handle = tpm2_session_get_handle(s);
        tpm2_session_free(&s);
    } break;
    case 'f':
        ctx.format = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = true;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "endorse-passwd",       required_argument, NULL, 'e' },
        { "owner-passwd",         required_argument, NULL, 'o' },
        { "handle",               required_argument, NULL, 'H' },
        { "ek-passwd",            required_argument, NULL, 'P' },
        { "algorithm",            required_argument, NULL, 'g' },
        { "file",                 required_argument, NULL, 'p' },
        { "session",              required_argument, NULL, 'S' },
        { "dbg",                  required_argument, NULL, 'd' },
        { "format",               required_argument, NULL, 'f' },
    };

    *opts = tpm2_options_new("e:o:H:P:g:p:S:d:f:", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.flags.f && !ctx.out_file_path) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return 1;
    }

    /* normalize 0 success 1 failure */
    return create_ek_handle(sapi_context) != true;
}
