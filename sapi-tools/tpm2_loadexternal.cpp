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

#ifdef _WIN32
#include "stdafx.h"
#else
#include <stdarg.h>
#endif

#ifndef UNICODE
#define UNICODE 1
#endif

#ifdef _WIN32
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define sprintf_s   snprintf
#define sscanf_s    sscanf
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include "tpm20.h"
#include "tpmsockets.h"
#include "common.h"

TPM_HANDLE handle2048rsa;
int debugLevel = 0;

int getHierarchyValue(const char *argValue, TPMI_RH_HIERARCHY *hierarchyValue)
{
    if(strlen(argValue) != 1)
    {
        printf("Wrong Hierarchy Value: %s\n",argValue);
        return -1;
    }
    switch(argValue[0])
    {
        case 'e':
            *hierarchyValue = TPM_RH_ENDORSEMENT;
            break;
        case 'o':
            *hierarchyValue = TPM_RH_OWNER;
            break;
        case 'p':
            *hierarchyValue = TPM_RH_PLATFORM;
            break;
        case 'n':
            *hierarchyValue = TPM_RH_NULL;
            break;
        default:
            printf("Wrong Hierarchy Value: %s\n",argValue);
            return -2;
    }
    return 0;
}

int loadExternal(TPMI_RH_HIERARCHY hierarchyValue, TPM2B_PUBLIC *inPublic, TPM2B_SENSITIVE *inPrivate, int r_flag)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_NAME nameExt = { { sizeof(TPM2B_NAME)-2, } };

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    if(r_flag == 0)
        rval = Tss2_Sys_LoadExternal(sysContext, 0, NULL, inPublic, hierarchyValue, &handle2048rsa, &nameExt, &sessionsDataOut);
    else
        rval = Tss2_Sys_LoadExternal(sysContext, 0, inPrivate , inPublic, hierarchyValue, &handle2048rsa, &nameExt, &sessionsDataOut);

    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nLoadExternal Failed ! ErrorCode: 0x%0x\n\n", rval);
        return -1;
    }
    printf("\nLoadExternal succ.\nLoadedHandle: 0x%08x\n\n", handle2048rsa);

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-H, --hierarchy <e|o|p|n>   Hierarchy with which the object area is associated\n"
            "\te  TPM_RH_ENDORSEMENT\n"
            "\to  TPM_RH_OWNER\n"
            "\tp  TPM_RH_PLATFORM\n"
            "\tn  TPM_RH_NULL\n"
        "-u, --pubfile   <publicKeyFileName>   The public portion of the object\n"
        "-r, --privfile  <privateKeyFileName>  The sensitive portion of the object, optional\n"
        "-C, --context <filename>   The file to save the object context, optional"
        "-p, --port  <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3> The level of debug message, default is 0, optional\n"
            "\t0 (high level test results)\n"
            "\t1 (test app send/receive byte streams)\n"
            "\t2 (resource manager send/receive byte streams)\n"
            "\t3 (resource manager tables)\n"
        "\n"
        "Example:\n"
        "%s -H <e|o|p|n> -u <pubKeyFileName> -r <privKeyFileName> \n"
        "%s -H <e|o|p|n> -u <pubKeyFileName>\n\n"// -i <simulator IP>\n\n",DEFAULT_TPM_PORT);
        ,name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char* argv[])
{

    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    TPMI_RH_HIERARCHY hierarchyValue;
    TPM2B_PUBLIC inPublic;
    TPM2B_SENSITIVE inPrivate;
    UINT16 size;

    memset(&inPublic,0,sizeof(TPM2B_PUBLIC));
    memset(&inPrivate,0,sizeof(TPM2B_SENSITIVE));

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvH:u:r:p:d:C:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"Hierachy",1,NULL,'H'},
      {"pubfile",1,NULL,'u'},
      {"privfile",1,NULL,'r'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {"context",1,NULL,'C'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        H_flag = 0,
        u_flag = 0,
        C_flag = 0,
        r_flag = 0;
    char *contextFile = NULL;

    if(argc == 1)
    {
        showHelp(argv[0]);
        return 0;
    }

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'h':
            h_flag = 1;
            break;
        case 'v':
            v_flag = 1;
            break;
        case 'H':
            if(getHierarchyValue(optarg,&hierarchyValue) != 0)
            {
                returnVal = -1;
                break;
            }
            printf("\nhierarchyValue: 0x%x\n\n",hierarchyValue);
            H_flag = 1;
            break;
        case 'u':
            size = sizeof(inPublic);
            if(loadDataFromFile(optarg, (UINT8 *)&inPublic, &size) != 0)
            {
                returnVal = -2;
                break;
            }
            u_flag = 1;
            break;
        case 'r':
            size = sizeof(inPrivate);
            if(loadDataFromFile(optarg, (UINT8 *)&inPrivate, &size) != 0)
            {
                returnVal = -3;
                break;
            }
            r_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -4;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -5;
            }
            break;
        case 'C':
            contextFile = optarg;
            if(contextFile == NULL || contextFile[0] == '\0')
            {
                returnVal = -6;
                break;
            }
            printf("contextFile = %s\n", contextFile);
            C_flag = 1;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -7;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -8;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag + H_flag + u_flag ;
    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -9;
        }
    }
    else if(flagCnt == 2 && H_flag == 1 && u_flag == 1)
    {

        prepareTest(hostName, port, debugLevel);

        returnVal = loadExternal(hierarchyValue, &inPublic, &inPrivate, r_flag);
        if(returnVal == 0 && C_flag)
            returnVal = saveTpmContextToFile(sysContext, handle2048rsa, contextFile);

        finishTest();

        if(returnVal)
            return -10;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -11;
    }

    return 0;
}
