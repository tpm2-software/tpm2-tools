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
#ifndef LIB_TPM2_NV_UTIL_H_
#define LIB_TPM2_NV_UTIL_H_

#include <tss2/tss2_esys.h>
#include <tss2/tss2_sys.h>

#include "log.h"
#include "tpm2_util.h"

/*
 * The default buffer size when one cannot be determined via get capability.
 */
#define NV_DEFAULT_BUFFER_SIZE 512

/**
 * Reads the public portion of a Non-Volatile (nv) index.
 * @param context
 *  The ESAPI context.
 * @param nv_index
 *  The index to read.
 * @param nv_public
 *  The public data structure to store the results in.
 * @return
 *  True on success, false otherwise.
 */
static inline bool tpm2_util_nv_read_public(ESYS_CONTEXT *context,
        TPMI_RH_NV_INDEX nv_index, TPM2B_NV_PUBLIC **nv_public) {

    TSS2_RC rval;
    ESYS_TR tr_object;

    rval = Esys_TR_FromTPMPublic(context, nv_index,
                                 ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &tr_object);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return false;
    }

    rval = Esys_NV_ReadPublic(context, tr_object,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                              nv_public, NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ReadPublic, rval);
        return false;
    }

    rval = Esys_TR_Close(context, &tr_object);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ReadPublic, rval);
        return false;
    }

    return true;
}

static inline bool tpm2_util_nv_read_public_sapi(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_RH_NV_INDEX nv_index, TPM2B_NV_PUBLIC *nv_public) {

    TPM2B_NAME nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_NV_ReadPublic(sapi_context, nv_index, NULL, nv_public,
            &nv_name, NULL));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_NV_ReadPublic, rval);
        return false;
    }

    return true;
}

/**
 * Retrieves the maximum transmission size for an NV buffer by
 * querying the capabilities for TPM2_PT_NV_BUFFER_MAX.
 * @param sapi_context
 *  The system api context
 * @param size
 *  The size of the buffer.
 * @return
 *  True on success, false otherwise.
 */
static inline bool tpm2_util_nv_max_buffer_size(TSS2_SYS_CONTEXT *sapi_context,
        UINT32 *size) {

    /* Get the maximum read block size */
    TPMS_CAPABILITY_DATA cap_data;
    TPMI_YES_NO more_data;
    TSS2_RC rval = TSS2_RETRY_EXP(
               Tss2_Sys_GetCapability (sapi_context, NULL,
                   TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1,
                   &more_data, &cap_data, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_NV_ReadPublic, rval);
        return false;
    }

    *size = cap_data.data.tpmProperties.tpmProperty[0].value;

    return true;
}

#endif /* LIB_TPM2_NV_UTIL_H_ */
