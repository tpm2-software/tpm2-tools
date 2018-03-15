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

#include <stdbool.h>

#include <tss2/tss2_sys.h>

#include "log.h"

#include "tpm2_capability.h"

bool tpm2_capability_get (TSS2_SYS_CONTEXT *sapi_ctx,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 count,
        TPMS_CAPABILITY_DATA *capability_data) {

    TPMI_YES_NO            more_data;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_GetCapability (sapi_ctx,
                                NULL,
                                capability,
                                property,
                                count,
                                &more_data,
                                capability_data,
                                NULL));

    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to GetCapability: capability: 0x%x, property: 0x%x",
                 capability, property);
        LOG_PERR(Tss2_Sys_GetCapability, rval);
        return false;
    } else if (more_data) {
        LOG_WARN("More data to be queried: capability: 0x%x, property: "
                 "0x%x\n", capability, property);
        return false;
    }

    return true;
}
