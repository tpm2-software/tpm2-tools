//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#ifndef LIB_TPM2_CAPABILITY_H_
#define LIB_TPM2_CAPABILITY_H_

#include <tss2/tss2_esys.h>

/**
 * Invokes GetCapability to retrieve the current value of a capability from the
 * TPM.
 * @param context
 *  Enhanced system api (ESAPI) context
 * @param capability
 *  the capability being requested from the TPM
 * @param property
 *  property
 * @param count
 *  maximum number of values to return
 * @param capability_data
 *  capability data structure to populate
 * @return
 *  True if the capability_data structure is successfully filled, False if the
 *  call to the TPM fails.
 */
bool tpm2_capability_get (ESYS_CONTEXT *context,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 count,
        TPMS_CAPABILITY_DATA **capability_data);

/**
 * Attempts to find a vacant handle in the persistent handle namespace.
 * @param ctx
 *  Enhanced System API (ESAPI) context
 * @param vacant
 *  the vacant handle found by the function if True returned
 * @return
 *  True if a vacant handle was found successfully, False otherwise.
 */
bool tpm2_capability_find_vacant_persistent_handle (ESYS_CONTEXT *ctx,
        UINT32 *vacant);

#endif /* LIB_TPM2_CAPABILITY_H_ */
