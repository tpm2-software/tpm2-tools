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
#include <stdio.h>
#include <stdlib.h>
#include "changeEndian.h"

#include <openssl/err.h>
#include <openssl/hmac.h>

static const EVP_MD *tpm_algorithm_to_openssl_digest(TPMI_ALG_HASH algorithm) {

    switch(algorithm) {
    case TPM_ALG_SHA1:
        return EVP_sha1();
    case ALG_SHA256_VALUE:
        return EVP_sha256();
    case TPM_ALG_SHA384:
        return EVP_sha384();
    case TPM_ALG_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
    /* no return, not possible */
}

//
//
TPM_RC KDFa( TPMI_ALG_HASH hashAlg, TPM2B *key, char *label,
    TPM2B *contextU, TPM2B *contextV, UINT16 bits, TPM2B_MAX_BUFFER  *resultKey )
{
    TPM2B_DIGEST tmpResult;
    TPM2B_DIGEST tpm2bLabel, tpm2bBits, tpm2b_i_2;
    UINT8 *tpm2bBitsPtr = &tpm2bBits.t.buffer[0];
    UINT8 *tpm2b_i_2Ptr = &tpm2b_i_2.t.buffer[0];
    TPM2B_DIGEST *bufferList[8];
    UINT32 bitsSwizzled, i_Swizzled;
    TPM_RC rval = TPM_RC_SUCCESS;
    int i, j;
    UINT16 bytes = bits / 8;
    
#ifdef DEBUG
    OpenOutFile( &outFp );
    TpmClientPrintf( 0, "KDFA, hashAlg = %4.4x\n", hashAlg );
    TpmClientPrintf( 0, "\n\nKDFA, key = \n" );
    PrintSizedBuffer( key );
    CloseOutFile( &outFp );
#endif
    
    resultKey->t .size = 0;
    
    tpm2b_i_2.t.size = 4;

    tpm2bBits.t.size = 4;
    bitsSwizzled = CHANGE_ENDIAN_DWORD( bits );
    *(UINT32 *)tpm2bBitsPtr = bitsSwizzled;

    for(i = 0; label[i] != 0 ;i++ );

    tpm2bLabel.t.size = i+1;
    for( i = 0; i < tpm2bLabel.t.size; i++ )
    {
        tpm2bLabel.t.buffer[i] = label[i];
    }
    
#ifdef DEBUG
    OpenOutFile( &outFp );
    TpmClientPrintf( 0, "\n\nKDFA, tpm2bLabel = \n" );
    PrintSizedBuffer( (TPM2B *)&tpm2bLabel );

    TpmClientPrintf( 0, "\n\nKDFA, contextU = \n" );
    PrintSizedBuffer( contextU );

    TpmClientPrintf( 0, "\n\nKDFA, contextV = \n" );
    PrintSizedBuffer( contextV );
    CloseOutFile( &outFp );
#endif
    
    resultKey->t.size = 0;

    i = 1;

    const EVP_MD *md = tpm_algorithm_to_openssl_digest(hashAlg);
    if (!md) {
        fprintf(stderr, "Algorithm not supported for hmac: %x\n", hashAlg);
        return TPM_RC_HASH;
    }

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    int rc = HMAC_Init_ex(&ctx, key->buffer, key->size, md, NULL);
    if (!rc) {
        fprintf(stderr, "HMAC Init failed: %s\n", ERR_error_string(rc, NULL));
        return TPM_RC_MEMORY;
    }

    while( resultKey->t.size < bytes )
    {
        TPM2B_DIGEST tmpResult;
        // Inner loop

        i_Swizzled = CHANGE_ENDIAN_DWORD( i );
        *(UINT32 *)tpm2b_i_2Ptr = i_Swizzled;

        j = 0;
        bufferList[j++] = (TPM2B_DIGEST *)&(tpm2b_i_2.b);
        bufferList[j++] = (TPM2B_DIGEST *)&(tpm2bLabel.b);
        bufferList[j++] = (TPM2B_DIGEST *)contextU;
        bufferList[j++] = (TPM2B_DIGEST *)contextV;
        bufferList[j++] = (TPM2B_DIGEST *)&(tpm2bBits.b);
        bufferList[j] = (TPM2B_DIGEST *)0;
#ifdef DEBUG
        OpenOutFile( &outFp );
        for( j = 0; bufferList[j] != 0; j++ )
        {
            TpmClientPrintf( 0, "\n\nbufferlist[%d]:\n", j );
            PrintSizedBuffer( &( bufferList[j]->b ) );
        }
        CloseOutFile( &outFp );
#endif

        int c;
        for(c=0; c < j; c++) {
            TPM2B_DIGEST *digest = bufferList[c];
            int rc =  HMAC_Update(&ctx, digest->b.buffer, digest->b.size);
            if (!rc) {
                fprintf(stderr, "HMAC Update failed: %s\n", ERR_error_string(rc, NULL));
                rval = TPM_RC_MEMORY;
                goto err;
            }
        }

        unsigned size = sizeof(tmpResult.t.buffer);
        int rc = HMAC_Final(&ctx, tmpResult.t.buffer, &size);
        if (!rc) {
            fprintf(stderr, "HMAC Final failed: %s\n", ERR_error_string(rc, NULL));
            rval = TPM_RC_MEMORY;
            goto err;
        }

        ConcatSizedByteBuffer( resultKey, &(tmpResult.b) );
    }

    // Truncate the result to the desired size.
    resultKey->t.size = bytes;

#ifdef DEBUG
    OpenOutFile( &outFp );
    TpmClientPrintf( 0, "\n\nKDFA, resultKey = \n" );
    PrintSizedBuffer( &( resultKey->b ) );
    CloseOutFile( &outFp );
#endif
    
err:
    HMAC_CTX_cleanup(&ctx);

    return rval;
}
