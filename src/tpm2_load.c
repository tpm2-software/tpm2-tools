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

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "common.h"

TPM_HANDLE handle2048rsa;
TPMS_AUTH_COMMAND sessionData;
bool hexPasswd = false;
int debugLevel = 0;

int
load (TSS2_SYS_CONTEXT *sapi_context,
      TPMI_DH_OBJECT    parentHandle,
      TPM2B_PUBLIC     *inPublic,
      TPM2B_PRIVATE    *inPrivate,
      const char       *outFileName,
      int               P_flag)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_NAME              nameExt     = { { sizeof(TPM2B_NAME)-2, } };

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;

    if(P_flag == 0)
        sessionData.hmac.t.size = 0;

    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;
    if (sessionData.hmac.t.size > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (hex2ByteStructure((char *)sessionData.hmac.t.buffer,
                              &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for parent Passwd.\n");
            return -1;
        }
    }

    rval = Tss2_Sys_Load (sapi_context,
                          parentHandle,
                          &sessionsData,
                          inPrivate,
                          inPublic,
                          &handle2048rsa,
                          &nameExt,
                          &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nLoad Object Failed ! ErrorCode: 0x%0x\n\n",rval);
        return -1;
    }
    printf("\nLoad succ.\nLoadedHandle: 0x%08x\n\n",handle2048rsa);

    if(saveDataToFile(outFileName, (UINT8 *)&nameExt, sizeof(nameExt)))
        return -2;

    return 0;
}

int
execute_tool (int              argc,
              char             *argv[],
              char             *envp[],
              common_opts_t    *opts,
              TSS2_SYS_CONTEXT *sapi_context)
{
    TPMI_DH_OBJECT parentHandle;
    TPM2B_PUBLIC  inPublic;
    TPM2B_PRIVATE inPrivate;
    UINT16 size;
    char outFilePath[PATH_MAX] = {0};
    char *contextFile = NULL;
    char *contextParentFilePath = NULL;

    memset(&inPublic,0,sizeof(TPM2B_PUBLIC));
    memset(&inPrivate,0,sizeof(TPM2B_SENSITIVE));

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "H:P:u:r:n:C:c:X";
    static struct option long_options[] = {
      {"parent",1,NULL,'H'},
      {"pwdp",1,NULL,'P'},
      {"pubfile",1,NULL,'u'},
      {"privfile",1,NULL,'r'},
      {"name",1,NULL,'n'},
      {"context",1,NULL,'C'},
      {"contextParent",1,NULL,'c'},
      {"passwdInHex",0,NULL,'X'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int H_flag = 0,
        P_flag = 0,
        u_flag = 0,
        r_flag = 0,
        c_flag = 0,
        C_flag = 0,
        n_flag = 0;

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'H':
            if(getSizeUint32Hex(optarg, &parentHandle) != 0)
            {
                returnVal = -1;
                break;
            }
            printf("\nparentHandle: 0x%x\n\n",parentHandle);
            H_flag = 1;
            break;
        case 'P':
            sessionData.hmac.t.size = sizeof(sessionData.hmac.t) - 2;
            if(str2ByteStructure(optarg,&sessionData.hmac.t.size,sessionData.hmac.t.buffer) != 0)
            {
                returnVal = -2;
                break;
            }
            P_flag = 1;
            break;

        case 'u':
            size = sizeof(inPublic);
            if(loadDataFromFile(optarg, (UINT8 *)&inPublic, &size) != 0)
            {
                returnVal = -3;
                break;
            }
            u_flag = 1;
            break;
        case 'r':
            size = sizeof(inPrivate);
            if(loadDataFromFile(optarg, (UINT8 *)&inPrivate, &size) != 0)
            {
                returnVal = -4;
                break;
            }
            r_flag = 1;
            break;
        case 'n':
            snprintf(outFilePath, sizeof(outFilePath), "%s", optarg);
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -5;
                break;
            }
            n_flag = 1;
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -7;
            }
            break;
        case 'c':
            contextParentFilePath = optarg;
            if(contextParentFilePath == NULL || contextParentFilePath[0] == '\0')
            {
                returnVal = -8;
                break;
            }
            printf("contextParentFile = %s\n", contextParentFilePath);
            c_flag = 1;
            break;
        case 'C':
            contextFile = optarg;
            if(contextFile == NULL || contextFile[0] == '\0')
            {
                returnVal = -9;
                break;
            }
            printf("contextFile = %s\n", contextFile);
            C_flag = 1;
            break;
        case 'X':
            hexPasswd = true;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -10;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -11;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;

    flagCnt = H_flag + u_flag +r_flag + n_flag + c_flag;
    if(flagCnt == 4 && (H_flag == 1 || c_flag == 1) && u_flag == 1 && r_flag == 1 && n_flag == 1)
    {
        if(c_flag) {
            returnVal = loadTpmContextFromFile (sapi_context,
                                                &parentHandle,
                                                contextParentFilePath);
        }
        if (returnVal == 0) {
            returnVal = load (sapi_context,
                              parentHandle,
                              &inPublic,
                              &inPrivate,
                              outFilePath,
                              P_flag);
        }
        if (returnVal == 0 && C_flag) {
            returnVal = saveTpmContextToFile (sapi_context,
                                              handle2048rsa,
                                              contextFile);
        }
        if(returnVal)
            return -13;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -14;
    }

    return 0;
}
