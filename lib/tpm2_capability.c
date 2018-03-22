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
#include "tpm2_util.h"

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

bool tpm2_capability_find_vacant_persistent_handle (TSS2_SYS_CONTEXT *sapi_ctx,
        UINT32 *vacant) {

    TPMS_CAPABILITY_DATA capability_data = TPMS_CAPABILITY_DATA_EMPTY_INIT;
    bool ret = tpm2_capability_get(sapi_ctx, TPM2_CAP_HANDLES,
                    TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES,
                    &capability_data);
    if (!ret) {
        return false;
    }

    bool handle_found = false;
    UINT32 count = capability_data.data.handles.count;
    if (count == 0) {
        /* There aren't any persistent handles, so use the first */
        *vacant = TPM2_PERSISTENT_FIRST;
        handle_found = true;
    } else if (count == TPM2_MAX_CAP_HANDLES) {
        /* All persistent handles are already in use */
        return false;
    } else if (count < TPM2_MAX_CAP_HANDLES) {
        /* iterate over used handles to ensure we're selecting
            the next available handle. */
        UINT32 i;
        for (i = TPM2_PERSISTENT_FIRST;
            i <= (UINT32)TPM2_PERSISTENT_LAST;
            ++i) {
            bool inuse = false;
            UINT32 c;
            for (c = 0; c < count; ++c) {
                if (capability_data.data.handles.handle[c] == i) {
                    inuse = true;
                    break;
                }
            }

            if (!inuse) {
                *vacant = i;
                handle_found = true;
                break;
            }
        }
    }

    return handle_found;
}
