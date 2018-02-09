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

 #include <openssl/err.h>
#include <openssl/hmac.h>

#include "log.h"
#include "tpm_kdfa.h"
#include "tpm2_openssl.h"
#include "tpm2_util.h"

TSS2_RC tpm_kdfa(TPMI_ALG_HASH hashAlg,
        TPM2B *key, char *label, TPM2B *contextU, TPM2B *contextV, UINT16 bits,
        TPM2B_MAX_BUFFER  *resultKey )
{
    TPM2B_DIGEST tpm2bLabel, tpm2bBits, tpm2b_i_2;
    UINT8 *tpm2bBitsPtr = &tpm2bBits.buffer[0];
    UINT8 *tpm2b_i_2Ptr = &tpm2b_i_2.buffer[0];
    TPM2B_DIGEST *bufferList[8];
    UINT32 bitsSwizzled, i_Swizzled;
    TSS2_RC rval = TPM2_RC_SUCCESS;
    int i, j;
    UINT16 bytes = bits / 8;

    resultKey->size = 0;

    tpm2b_i_2.size = 4;

    tpm2bBits.size = 4;
    bitsSwizzled = tpm2_util_endian_swap_32( bits );
    *(UINT32 *)tpm2bBitsPtr = bitsSwizzled;

    for(i = 0; label[i] != 0 ;i++ );

    tpm2bLabel.size = i+1;
    for( i = 0; i < tpm2bLabel.size; i++ )
    {
        tpm2bLabel.buffer[i] = label[i];
    }

    resultKey->size = 0;

    i = 1;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(hashAlg);
    if (!md) {
        LOG_ERR("Algorithm not supported for hmac: %x", hashAlg);
        return TPM2_RC_HASH;
    }

    HMAC_CTX *ctx = tpm2_openssl_hmac_new();
    if (!ctx) {
        LOG_ERR("HMAC context allocation failed");
        return TPM2_RC_MEMORY;
    }

    int rc = HMAC_Init_ex(ctx, key->buffer, key->size, md, NULL);
    if (!rc) {
        LOG_ERR("HMAC Init failed: %s", ERR_error_string(rc, NULL));
        rval = TPM2_RC_MEMORY;
        goto err;
    }

    // TODO Why is this a loop? It appears to only execute once.
    while( resultKey->size < bytes )
    {
        TPM2B_DIGEST tmpResult;
        // Inner loop

        i_Swizzled = tpm2_util_endian_swap_32( i );
        *(UINT32 *)tpm2b_i_2Ptr = i_Swizzled;

        j = 0;
        bufferList[j++] = (TPM2B_DIGEST *)&(tpm2b_i_2);
        bufferList[j++] = (TPM2B_DIGEST *)&(tpm2bLabel);
        bufferList[j++] = (TPM2B_DIGEST *)contextU;
        bufferList[j++] = (TPM2B_DIGEST *)contextV;
        bufferList[j++] = (TPM2B_DIGEST *)&(tpm2bBits);
        bufferList[j] = (TPM2B_DIGEST *)0;

        int c;
        for(c=0; c < j; c++) {
            TPM2B_DIGEST *digest = bufferList[c];
            int rc =  HMAC_Update(ctx, digest->buffer, digest->size);
            if (!rc) {
                LOG_ERR("HMAC Update failed: %s", ERR_error_string(rc, NULL));
                rval = TPM2_RC_MEMORY;
                goto err;
            }
        }

        unsigned size = sizeof(tmpResult.buffer);
        int rc = HMAC_Final(ctx, tmpResult.buffer, &size);
        if (!rc) {
            LOG_ERR("HMAC Final failed: %s", ERR_error_string(rc, NULL));
            rval = TPM2_RC_MEMORY;
            goto err;
        }

        tmpResult.size = size;

        bool res = tpm2_util_concat_buffer(resultKey, (TPM2B *)&tmpResult);
        if (!res) {
            rval = TSS2_SYS_RC_BAD_VALUE;
            goto err;
        }
    }

    // Truncate the result to the desired size.
    resultKey->size = bytes;

err:
    tpm2_openssl_hmac_free(ctx);

    return rval;
}
