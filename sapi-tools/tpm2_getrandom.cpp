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

#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include <ctype.h>

#include "tpm20.h"
#include "tpmsockets.h"
#include "common.h"

int debugLevel = 0;

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "Usage: %s  [-h/--help]\n"
            "   or: %s [-v/--version]\n"
            "   or: %s [-s/--size <bytesRequested>] [-o/--of <outfilename>] \n"
            "   or: %s  [-s/--size <bytesRequested>] [-o/--of <outfilename>]\n"
            "                      [-i/--ip <ipAddress>] [-p/--port <port>] [-d/--dbg <dbgLevel>]\n"
            "\nwhere:\n\n"
            "   -h/--help                       display this help and exit.\n"
            "   -v/--version                    display version information and exit.\n"
            "   -s/--size <bytesRequested>      specifies the size of the bytesRequested.\n"
            "   -o/--of <outfilename>           specifies the filename of output:\n"
            "   -p/--port <port>                specifies the port number (default:%d).\n"
            "   -d/--dbg <dbgLevel>             specifies level of debug messages:\n"
            "                                     0 (high level test results)\n"
            "                                     1 (test app send/receive byte streams)\n"
            "                                     2 (resource manager send/receive byte streams)\n"
            "                                     3 (resource manager tables)\n"
            "\nexample:\n"
            "   %s -s 20 -o random.out \n"
            , name, name, name, name, name, DEFAULT_RESMGR_TPM_PORT, name);
}

int getRandom(const char *outFileName, UINT16 bytesRequested)
{
    TPM_RC rval;
    TPM2B_DIGEST        randomBytes;

    rval = Tss2_Sys_GetRandom(sysContext, NULL, bytesRequested, &randomBytes, NULL);
    if (rval != TSS2_RC_SUCCESS)
    {
        printf("\n......TPM2_GetRandom Error. TPM Error:0x%x......\n", rval);
        return -1;
    }
    printf("\nGetRandom succ...\n");
    printf("byte size: %d\n",randomBytes.t.size);
    for(UINT16 i = 0; i < randomBytes.t.size; i++)
        printf(" 0x%2.2X",randomBytes.t.buffer[i]);
    printf("\n");

    if(saveDataToFile(outFileName, (UINT8 *)randomBytes.t.buffer, randomBytes.t.size))
        return -2;

    return 0;
}

int main(int argc, char* argv[])
{
    UINT16 size=20;
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    int returnVal = 0;
    char outFileName[PATH_MAX] = {0};

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    const char *optstring = "s:o:p:d:hv";
    int opt = -1;

    static struct option long_Opts[] = {
        { "size",1,NULL,'s' },
        { "of",1, NULL,'o' },
        { "port",1,NULL,'p' },
        { "dbg", 1,NULL,'d' },
        { "help",0,NULL,'h' },
        { "version",0,NULL,'v' },
        { 0,0,0,0 },
    };

    int flagCnt = 0,
        s_flag=0,
        o_flag=0,
        h_flag=0,
        v_flag=0;

    if( argc > (int)(2*sizeof(long_Opts)/sizeof(struct option)) || argc == 1)
    {
        showArgMismatch(argv[0]);
        return -1;
    }

    while((opt = getopt_long(argc,argv,optstring,long_Opts,NULL)) != -1 && returnVal == 0)
    {
        switch (opt) {
        case 'h':
            h_flag = 1;
            //  showHelp();
            break;
        case '?':
            returnVal = -2;
            break;
        case 'v':
            //      showVersion();
            v_flag = 1;
            break;

        case 's':
            if(getSizeUint16(optarg, &size))
            {
                printf(" s must go with the size number.\n");
                returnVal = -3;
                break;
            }
            s_flag = 1;
            break;

        case 'o':
            if (optarg==NULL)
            {
                printf("\n Please don't forget to specified the output file! \n");
                returnVal = -4;
                break;
            }
            safeStrNCpy(outFileName, optarg, sizeof(outFileName));
            o_flag=1;
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

        default:
            showArgMismatch(argv[0]);
            exit(-7);
        }
    };

    if(returnVal != 0)
        return returnVal;

    flagCnt = h_flag + v_flag + o_flag + s_flag;
    if (flagCnt == 1)
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
    else if(flagCnt == 2 && h_flag != 1 && v_flag !=1)
    {
        prepareTest(hostName, port, debugLevel);

        returnVal = getRandom(outFileName, size);

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
