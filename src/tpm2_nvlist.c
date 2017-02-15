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
#include <stdio.h>

#include <sapi/tpm20.h>
#include "changeEndian.h"

#include "log.h"
#include "main.h"
#include "options.h"

static bool nv_read_public(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_RH_NV_INDEX nv_index) {

    TPM2B_NAME nv_name = {
            { sizeof(TPM2B_NAME)-2, }
    };

    TPM2B_NV_PUBLIC nv_public = {
            { 0, }
    };

    TPM_RC rval = Tss2_Sys_NV_ReadPublic(sapi_context, nv_index, 0, &nv_public,
            &nv_name, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("NVReadPublic Failed ! ErrorCode: 0x%0x\n", rval);
        return false;
    }

    printf("  {\n");
    printf("\tHash algorithm(nameAlg):%d\n ", nv_public.t.nvPublic.nameAlg);
    printf("\tThe Index attributes(attributes):0x%x\n ",
            nv_public.t.nvPublic.attributes.val);
    printf("\tThe size of the data area(dataSize):%d\n ",
            nv_public.t.nvPublic.dataSize);
    printf("  }\n");

    return true;
}

static bool nv_list(TSS2_SYS_CONTEXT *sapi_context) {

    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    TPM_RC rval = Tss2_Sys_GetCapability(sapi_context, 0, TPM_CAP_HANDLES,
            CHANGE_ENDIAN_DWORD(TPM_HT_NV_INDEX),
            TPM_PT_NV_INDEX_MAX, &moreData, &capabilityData, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("GetCapability:Get NV Index list Error. TPM Error:0x%x", rval);
        return false;
    }

    printf("%d NV indexes defined.\n", capabilityData.data.handles.count);

    UINT32 i;
    for (i = 0; i < capabilityData.data.handles.count; i++) {
        printf("\n  %d. NV Index: 0x%x\n", i,
                capabilityData.data.handles.handle[i]);
        bool result = nv_read_public(sapi_context,
                capabilityData.data.handles.handle[i]);
        if (!result) {
            return false;
        }
    }
    printf("\n");

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void) argc;
    (void) argv;
    (void) envp;
    (void) opts;

    return nv_list(sapi_context) != 0;
}
