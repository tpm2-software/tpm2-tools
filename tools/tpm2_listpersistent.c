//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"

int readPublic(TSS2_SYS_CONTEXT *sapi_context,
               TPMI_DH_OBJECT    objectHandle)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_PUBLIC outPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    rval = Tss2_Sys_ReadPublic(sapi_context, objectHandle, 0, &outPublic, &name, &qualifiedName, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nTPM2_ReadPublic error: rval = 0x%0x\n\n",rval);
        return -1;
    }

    printf("  {\n");
    printf("\tType: 0x%x\n ", outPublic.t.publicArea.type);
    printf("\tHash algorithm(nameAlg): 0x%x\n ", outPublic.t.publicArea.nameAlg);
    printf("\tAttributes: 0x%x\n", outPublic.t.publicArea.objectAttributes.val);
    printf("  }\n");

    return 0;
}

int
execute_tool (int              argc,
              char             *argv[],
              char             *envp[],
              common_opts_t    *opts,
              TSS2_SYS_CONTEXT *sapi_context)
{
    (void) opts;
    (void) envp;
    (void) argc;
    (void) argv;

    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    UINT32 rval;

    UINT32 property = tpm2_util_endian_swap_32(TPM_HT_PERSISTENT);
    rval = Tss2_Sys_GetCapability( sapi_context, 0, TPM_CAP_HANDLES,
                                   property, TPM_PT_HR_PERSISTENT, &moreData,
                                   &capabilityData, 0 );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......GetCapability: Get persistent object list Error."
               " TPM Error:0x%x......\n", rval);
        return 1;
    }

    printf( "%d persistent objects defined.\n", capabilityData.data.handles.count);
    UINT32 i;
    for( i=0; i < capabilityData.data.handles.count; i++ )
    {
        printf("\n  %d. Persistent handle: 0x%x\n", i, capabilityData.data.handles.handle[i]);
        if(readPublic(sapi_context, capabilityData.data.handles.handle[i]))
            return 2;
    }
    printf("\n");

    return 0;
}
