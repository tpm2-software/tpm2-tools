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

int debugLevel = 0;

int readPublic(TPMI_DH_OBJECT objectHandle, const char *outFilePath)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_PUBLIC outPublic;
    TPM2B_NAME   name;
    TPM2B_NAME   qualifiedName;

    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    outPublic.t.size = 0;
    name.t.size = 0;
    qualifiedName.t.size = 0;

    rval = Tss2_Sys_ReadPublic(sysContext, objectHandle, 0, &outPublic, &name, &qualifiedName, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nTPM2_ReadPublic error: rval = 0x%0x\n\n",rval);
        return -1;
    }

    printf("\nTPM2_ReadPublic OutPut: \n");
    printf("name: \n");
    for(UINT16 i = 0; i < name.t.size; i++)
        printf("%02x ",name.t.name[i]);
    printf("\n");

    printf("qualifiedName: \n");
    for(UINT16 j = 0; j < qualifiedName.t.size; j++)
        printf("%02x ",qualifiedName.t.name[j]);
    printf("\n");

    if(saveDataToFile(outFilePath, (UINT8 *)&outPublic, sizeof(outPublic)))
        return -2;

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-H, --object <objectHandle>   The loaded object handle \n"
        "-c, --contextObject <filename>    filename for object context\n"
        "-o, --opu    <publicKeyFileName>  The output file path,\n"
        "                                  recording the readout public portion of the object\n"
        "-p, --port  <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3> The level of debug message, default is 0, optional\n"
            "\t0 (high level test results)\n"
            "\t1 (test app send/receive byte streams)\n"
            "\t2 (resource manager send/receive byte streams)\n"
            "\t3 (resource manager tables)\n"
        "\n"
        "Example:\n"
        "%s -H 0x80000000 -opu <pubKeyFileName> \n"
        , name, DEFAULT_RESMGR_TPM_PORT, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    TPMI_DH_OBJECT objectHandle;
    char outFilePath[PATH_MAX] = {0};
    char *contextFile = NULL;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvH:o:p:d:c:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"object",1,NULL,'H'},
      {"opu",1,NULL,'o'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {"contextObject",1,NULL,'c'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        H_flag = 0,
        c_flag = 0,
        o_flag = 0;

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
            if(getSizeUint32Hex(optarg,&objectHandle) != 0)
            {
                returnVal = -1;
                break;
            }
            printf("\nobject handle: 0x%x\n\n",objectHandle);
            H_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -2;
                break;
            }
            o_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -3;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -4;
            }
            break;
        case 'c':
            contextFile = optarg;
            if(contextFile == NULL || contextFile[0] == '\0')
            {
                returnVal = -5;
                break;
            }
            printf("contextFile = %s\n", contextFile);
            c_flag = 1;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -6;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -7;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;

    flagCnt = h_flag + v_flag + H_flag + o_flag + c_flag;
    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -8;
        }
    }
    else if(flagCnt == 2 && (H_flag == 1 || c_flag) && o_flag == 1)
    {
        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &objectHandle, contextFile);
        if(returnVal == 0)
            returnVal = readPublic(objectHandle, outFilePath);

        finishTest();

        if(returnVal)
            return -9;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -10;
    }

    return 0;
}
