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

#include <tss2/tpm20.h>
#include <tcti/tcti_socket.h>
#include "changeEndian.h"
#include "common.h"

int debugLevel = 0;

int readPublic(TPMI_DH_OBJECT objectHandle)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_PUBLIC outPublic = { { 0, } };
    TPM2B_NAME   name = { { sizeof(TPM2B_NAME)-2, } };
    TPM2B_NAME   qualifiedName = { { sizeof(TPM2B_NAME)-2, } };

    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    rval = Tss2_Sys_ReadPublic(sysContext, objectHandle, 0, &outPublic, &name, &qualifiedName, &sessionsDataOut);
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

int listPersistent()
{
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    UINT32 rval;

    rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_HANDLES,
                                   CHANGE_ENDIAN_DWORD(TPM_HT_PERSISTENT),
                                   TPM_PT_HR_PERSISTENT, &moreData,
                                   &capabilityData, 0 );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......GetCapability: Get persistent object list Error."
               " TPM Error:0x%x......\n", rval);
        return -1;
    }

    printf( "%d persistent objects defined.\n", capabilityData.data.handles.count);
    for( UINT32 i=0; i < capabilityData.data.handles.count; i++ )
    {
        printf("\n  %d. Persistent handle: 0x%x\n", i, capabilityData.data.handles.handle[i]);
        if(readPublic(capabilityData.data.handles.handle[i]))
            return -2;
    }
    printf("\n");

    return 0;
}

void showHelp(const char *name)
{
    printf("Usage: %s [-h/--help]\n"
           "   or: %s [-v/--version]\n"
           "   or: %s\n"
           "   or: %s [-p/--port <port>] [-d/--dbg <dbgLevel>]\n"
           "\nwhere:\n\n"
           "   -h/--help                       display this help and exit.\n"
           "   -v/--version                    display version information and exit.\n"
           "   -p/--port <port>                specifies the port number, default %d, optional\n"
           "   -d/--dbg <dbgLevel>             specifies level of debug messages, optional:\n"
           "                                     0 (high level test results)\n"
           "                                     1 (test app send/receive byte streams)\n"
           "                                     2 (resource manager send/receive byte streams)\n"
           "                                     3 (resource manager tables)\n"
           , name, name, name, name, DEFAULT_RESMGR_TPM_PORT);
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
    int opt = -1;
    int returnVal = 0;

    struct option sOptions[] =
    {
        { "port"     , required_argument, NULL, 'p' },
        { "dbg"      , required_argument, NULL, 'd' },
        { "help"     , no_argument,       NULL, 'h' },
        { "version"  , no_argument,       NULL, 'v' },
        { 0          , 0,                    0,  0  },
    };

    if( argc > (int)(2*sizeof(sOptions)/sizeof(struct option)) )
    {
        showArgMismatch(argv[0]);
        return -1;
    }

    while( ( opt = getopt_long(argc, argv, "p:d:hv", sOptions, NULL) ) != -1 )
    {
        switch(opt)
        {
        case 'h':
        case '?':
            showHelp(argv[0]);
            return 0;
        case 'v':
            showVersion(argv[0]);
            return 0;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                return -2;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                return -3;
            }
            break;
        default:
            break;
        }
    };

    prepareTest(hostName, port, debugLevel);

    returnVal = listPersistent();

    finishTest();

    if(returnVal)
        return -4;

    return 0;
}
