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

#include <tss2/tss2_sys.h>

#include "tpm2_util.h"

static UINT32 LoadExternalHMACKey(TSS2_SYS_CONTEXT *sapi_contex, TPMI_ALG_HASH hashAlg, TPM2B *key, TPM2_HANDLE *keyHandle, TPM2B_NAME *keyName )
{
    TPM2B keyAuth = {
            .size = 0,
    };

    TPM2B_SENSITIVE inPrivate;
    TPM2B_PUBLIC inPublic;


    inPrivate.sensitiveArea.sensitiveType = TPM2_ALG_KEYEDHASH;
    inPrivate.size = tpm2_util_copy_tpm2b((TPM2B *)&inPrivate.sensitiveArea.authValue, &keyAuth);
    inPrivate.sensitiveArea.seedValue.size = 0;
    inPrivate.size += tpm2_util_copy_tpm2b((TPM2B *)&inPrivate.sensitiveArea.sensitive.bits, key);
    inPrivate.size += 2 * sizeof( UINT16 );

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_NULL;
    *( UINT32 *)&( inPublic.publicArea.objectAttributes )= 0;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
    inPublic.publicArea.unique.keyedHash.size = 0;

    keyName->size = sizeof( TPM2B_NAME ) - 2;
    return Tss2_Sys_LoadExternal(sapi_contex, 0, &inPrivate, &inPublic, TPM2_RH_NULL, keyHandle, keyName, 0 );
}


//
// This function does an HMAC on a null-terminated list of input buffers.
//
TSS2_RC tpm_hmac(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hashAlg, TPM2B *key, TPM2B **bufferList, TPM2B_DIGEST *result )
{
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B emptyBuffer;
    TPMT_TK_HASHCHECK validation;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .nonce = {
                    .size = 0,
            },
            .sessionAttributes = 0,
    }}};

    UINT32 rval;
    TPM2_HANDLE keyHandle;
    TPM2B_NAME keyName;

    TPM2B_AUTH nullAuth = {
                .size = 0,
    };

    TPM2B keyAuth = {
            .size = 0,
    };

    // Set result size to 0, in case any errors occur
    result->size = 0;

    rval = LoadExternalHMACKey(sapi_context, hashAlg, key, &keyHandle, &keyName );
    if( rval != TPM2_RC_SUCCESS )
    {
        return( rval );
    }

    // Init input sessions struct
    sessionsData.count = 1;
    tpm2_util_copy_tpm2b((TPM2B *)&sessionsData.auths[0].hmac, &keyAuth);

    // Init sessions out struct

    emptyBuffer.size = 0;

    rval = Tss2_Sys_HMAC_Start( sapi_context, keyHandle, &sessionsData, &nullAuth, hashAlg, &sequenceHandle, 0 );

    if( rval != TPM2_RC_SUCCESS )
        return( rval );

    unsigned i;
    for( i = 0; bufferList[i] != 0; i++ )
    {
        rval = Tss2_Sys_SequenceUpdate ( sapi_context, sequenceHandle, &sessionsData, (TPM2B_MAX_BUFFER *)( bufferList[i] ), &sessionsDataOut );

        if( rval != TPM2_RC_SUCCESS )
            return( rval );
    }

    result->size = sizeof( TPM2B_DIGEST ) - 2;
    rval = Tss2_Sys_SequenceComplete ( sapi_context, sequenceHandle, &sessionsData, ( TPM2B_MAX_BUFFER *)&emptyBuffer,
            TPM2_RH_PLATFORM, result, &validation, &sessionsDataOut );

    if( rval != TPM2_RC_SUCCESS )
        return( rval );

    rval = Tss2_Sys_FlushContext( sapi_context, keyHandle );

    return rval;
}
