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
UINT32 nvIndex;
UINT32 authHandle;
char handlePasswd[sizeof(TPMU_HA)];

int nvSpaceRelease()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    if (strlen(handlePasswd) > 0)
    {
        sessionData.hmac.t.size = strlen(handlePasswd);
        memcpy( &sessionData.hmac.t.buffer[0], handlePasswd, sessionData.hmac.t.size );
    }

    rval = Tss2_Sys_NV_UndefineSpace( sysContext, authHandle, nvIndex, &sessionsData, 0 );
    if(rval != TPM_RC_SUCCESS)
    {
        printf( "Failed to release NV area at index 0x%x (%d).Error:0x%x\n", nvIndex, nvIndex, rval );
        return -1;
    }
    printf( "Success to release NV area at index 0x%x (%d).\n", nvIndex, nvIndex);

    return 0;
}

void showHelp(const char *name)
{
    printf("Usage: %s [-h/--help]\n"
           "   or: %s [-v/--version]\n"
           "   or: %s [-x/--index <nvIdx>] [-a/--authHandle <hexHandle>] [-P/--handlePasswd <string>]\n"
           "   or: %s [-x/--index <nvIdx>] [-a/--authHandle <hexHandle>] [-P/--handlePasswd <string>]\n"
           "                      [-p/--port <port>] [-d/--dbg <dbgLevel>]\n"
           "\nwhere:\n\n"
           "   -h/--help                       display this help and exit.\n"
           "   -v/--version                    display version information and exit.\n"
           "   -x/--index <nvIdx>              specifies the index of the NV area.\n"
           "   -a/--authHandle <hexHandle>     specifies the handle used to authorize:\n"
           "                                     0x40000001 (TPM_RH_OWNER)\n"
           "                                     0x4000000C (TPM_RH_PLATFORM)\n"
           "   -P/--handlePasswd <string>      specifies the password of authHandle.\n"
           "   -p/--port <port>                specifies the port number, default:%d, optional\n"
           "   -d/--dbg <dbgLevel>             specifies level of debug messages, optional:\n"
           "                                     0 (high level test results)\n"
           "                                     1 (test app send/receive byte streams)\n"
           "                                     2 (resource manager send/receive byte streams)\n"
           "                                     3 (resource manager tables)\n"
           "\nexample:\n"
           "   %s -x 0x1500016 -a 0x40000001 -P passwd\n"
           , name, name, name, name, DEFAULT_RESMGR_TPM_PORT, name);
}

int main(int argc, char* argv[])
{
    int opt;
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
    int returnVal = 0;


    struct option sOpts[] = {
        { "index"       , required_argument, NULL, 'x' },
        { "authHandle"  , required_argument, NULL, 'a' },
        { "handlePasswd", required_argument, NULL, 'P' },
        { "port"        , required_argument, NULL, 'p' },
        { "dbg"         , required_argument, NULL, 'd' },
        { "help"        , no_argument,       NULL, 'h' },
        { "version"     , no_argument,       NULL, 'v' },
        { NULL          , no_argument,       NULL,  0  },
    };

    if( argc == 1 )
    {
        showHelp(argv[0]);
        return 0;
    }

    if( argc > (int)(2*sizeof(sOpts)/sizeof(struct option)) )
    {
        showArgMismatch(argv[0]);
        return -1;
    }

    while ( ( opt = getopt_long( argc, argv, "x:a:P:p:d:hv", sOpts, NULL ) ) != -1 )
    {
        switch ( opt ) {
        case 'h':
        case '?':
            showHelp(argv[0]);
            return 0;
        case 'v':
            showVersion(argv[0]);
            return 0;

        case 'x':
            if( getSizeUint32Hex(optarg, &nvIndex) != 0 )
            {
                return -2;
            }
            break;

        case 'a':
            if( getSizeUint32Hex(optarg, &authHandle) != 0 )
            {
                return -3;
            }
            break;

        case 'P':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the handle password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -4;
            }
            safeStrNCpy(handlePasswd, optarg, sizeof(handlePasswd));
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                return -5;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                return -6;
            }
            break;

        default:
            showArgMismatch(argv[0]);
            return -7;
        }
    }

    if( nvIndex == 0 )
    {
        printf("\nYou must provide an index (!= 0) for the NVRAM area.\n");
        return -8;
    }

    if( authHandle == 0 )
    {
        printf("\nYou must provide an right auth handle for this operation.\n");
        return -9;
    }

    prepareTest(hostName, port, debugLevel);

    returnVal = nvSpaceRelease();

    finishTest();

    if(returnVal)
        return -10;

    return 0;
}
