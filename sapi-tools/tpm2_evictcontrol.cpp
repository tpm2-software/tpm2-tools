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
TPMS_AUTH_COMMAND sessionData;

int evictControl(TPMI_RH_PROVISION auth, TPMI_DH_OBJECT objectHandle,TPMI_DH_OBJECT persistentHandle, int P_flag)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

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

    rval = Tss2_Sys_EvictControl(sysContext, auth, objectHandle, &sessionsData, persistentHandle,&sessionsDataOut);

    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nEvictControl Failed, error code: 0x%0x\n\n",rval);
        return -1;
    }
    printf("\nEvictControl succ.\n");

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-A, --auth <o | p | n>   the authorization used to authorize the commands\n"
            "\to  TPM_RH_OWNER\n"
            "\tp  TPM_RH_PLATFORM\n"
        "-H, --handle    <objectHandle>        the handle of a loaded object\n"
        "-c, --context <filename>              filename for object context\n"
        "-S, --persistent<persistentHandle>    the persistent handle for objectHandle\n"
        "-P, --pwda      <authorizationPassword>   authrization password, optional\n"
        "-p, --port  <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3> The level of debug message, default is 0, optional\n"
            "\t0 (high level test results)\n"
            "\t1 (test app send/receive byte streams)\n"
            "\t2 (resource manager send/receive byte streams)\n"
            "\t3 (resource manager tables)\n"
        "\n"
        "Example:\n"
        "%s -A n -H 0x80000000 -S 0x8101002 -P abc123 \n"
        "%s -A p -H 0x80000000 -S 0x8101002\n\n"// -i <simulator IP>\n\n",DEFAULT_TPM_PORT);
        ,name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char* argv[])
{

    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT; //DEFAULT_TPM_PORT;

    TPMI_RH_PROVISION auth = TPM_RH_NULL;
    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_OBJECT persistentHandle;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvA:H:S:P:p:d:c:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"auth",1,NULL,'A'},
      {"handle",1,NULL,'H'},
      {"persistent",1,NULL,'S'},
      {"pwda",1,NULL,'P'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {"context",1,NULL,'c'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        A_flag = 0,
        H_flag = 0,
        S_flag = 0,
        c_flag = 0,
        P_flag = 0;
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
        case 'A':
            if(strcmp(optarg,"o") == 0 || strcmp(optarg,"O") == 0)
                auth = TPM_RH_OWNER;
            else if(strcmp(optarg,"p") == 0 || strcmp(optarg,"P") == 0)
                auth = TPM_RH_PLATFORM;
            else
            {
                printf("ERROR: auth '%s' not supported!\n", optarg);
                returnVal = -1;
                break;
            }
            A_flag = 1;
            break;
        case 'H':
            if(getSizeUint32Hex(optarg, &objectHandle) != 0)
            {
                returnVal = -2;
                break;
            }
            printf("\nobjecttHanlde: 0x%x\n\n",objectHandle);
            H_flag = 1;
            break;
        case 'S':
            if(getSizeUint32Hex(optarg, &persistentHandle) != 0)
            {
                returnVal = -3;
                break;
            }
            printf("\npersistentHanlde: 0x%x\n\n",persistentHandle);
            S_flag = 1;
            break;
        case 'P':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the authenticating password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                returnVal = -4;
                break;
            }
            if( strlen(optarg) > 0 )
            {
                sessionData.hmac.t.size = strlen(optarg);
                safeStrNCpy( (char *)&sessionData.hmac.t.buffer[0], optarg, sizeof(sessionData.hmac.t.buffer) );
            }
            P_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -5;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -6;
            }
            break;
        case 'c':
            contextFile = optarg;
            if(contextFile == NULL || contextFile[0] == '\0')
            {
                returnVal = -7;
                break;
            }
            printf("contextFile = %s\n", contextFile);
            c_flag = 1;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -8;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -9;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag + A_flag + H_flag + S_flag + c_flag;
    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -10;
        }
    }
    else if(flagCnt == 3 && A_flag == 1 && (H_flag == 1 || c_flag) && S_flag == 1)
    {
        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &objectHandle, contextFile);
        if (returnVal == 0)
            returnVal = evictControl(auth, objectHandle, persistentHandle, P_flag);

        finishTest();

        if(returnVal)
            return -11;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -12;
    }

    return 0;
}
