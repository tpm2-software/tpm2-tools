//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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
#ifndef SRC_TPM_HASH_H_
#define SRC_TPM_HASH_H_

#include <stdbool.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>

/**
 * Hashes a BYTE array via the tpm.
 * @param context
 *  The esapi context.
 * @param hash_alg
 *  The hashing algorithm to use.
 * @param hierarchy
 *  The hierarchy.
 * @param buffer
 *  The data to hash.
 * @param length
 *  The length of the data.
 * @param result
 *  The digest result.
 * @param validation
 *  The validation ticket. Note that some hierarchies don't produce a
 *  validation ticket and thus size will be 0.
 * @return
 *  True on success, false otherwise.
 */
bool tpm2_hash_compute_data(ESYS_CONTEXT *context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST **result, TPMT_TK_HASHCHECK **validation);

bool tpm2_hash_compute_data_sapi(TSS2_SYS_CONTEXT *context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST *result, TPMT_TK_HASHCHECK *validation);

/**
 * Hashes a FILE * object via the tpm.
 * @param context
 *  The esapi context.
 * @param hash_alg
 *  The hashing algorithm to use.
 * @param hierarchy
 *  The hierarchy.
 * @param input
 *  The FILE object to hash.
 * @param result
 *  The digest result.
 * @param validation
 *  The validation ticket. Note that some hierarchies don't produce a
 *  validation ticket and thus size will be 0.
 * @return
 *  True on success, false otherwise.
 */
bool tpm2_hash_file(ESYS_CONTEXT *context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation);

bool tpm2_hash_file_sapi(TSS2_SYS_CONTEXT *context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST *result,
        TPMT_TK_HASHCHECK *validation);

#endif /* SRC_TPM_HASH_H_ */
