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

#include <sapi/tpm20.h>
#include "sample.h"

//
// This function does a hash on a string of data.
//
UINT32 TpmHash( TPMI_ALG_HASH hashAlg, UINT16 size, BYTE *data, TPM2B_DIGEST *result )
{
    TPM_RC rval;
    TPM2B_MAX_BUFFER dataSizedBuffer;
    UINT16 i;
    TSS2_SYS_CONTEXT *sysContext;
    
    dataSizedBuffer.t.size = size;
    for( i = 0; i < size; i++ )
        dataSizedBuffer.t.buffer[i] = data[i];
    
    sysContext = InitSysContext( 3000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;
    
    rval = Tss2_Sys_Hash ( sysContext, 0, &dataSizedBuffer, hashAlg, TPM_RH_NULL, result, 0, 0);

    TeardownSysContext( &sysContext );
    
    return rval;
}

//
// This function does a hash on an array of data strings and creates syscontext
//
UINT32 TpmHashSequence( TPMI_ALG_HASH hashAlg, UINT8 numBuffers, 
    TPM2B_DIGEST *bufferList, TPM2B_DIGEST *result ) {
    TSS2_SYS_CONTEXT *sysContext=InitSysContext(3000, resMgrTctiContext, &abiVersion);

    if( sysContext == 0 ){
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;
    }
    TPM_RC rval = tpm_hash_sequence(sysContext, hashAlg, numBuffers, 
        bufferList, result);

    TeardownSysContext( &sysContext );
    return rval;
}

