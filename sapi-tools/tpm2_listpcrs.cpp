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

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
    (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define CLEAR_PCR_SELECT_BITS( pcrSelection ) \
    (pcrSelection).pcrSelect[0] = 0; \
    (pcrSelection).pcrSelect[1] = 0; \
    (pcrSelection).pcrSelect[2] = 0;

#define SET_PCR_SELECT_SIZE( pcrSelection, size ) \
    (pcrSelection).sizeofSelect = size;

int debugLevel = 0;
FILE *fp = NULL;
char outFilePath[PATH_MAX];
const struct {
    TPMI_ALG_HASH alg;
    const char *desc;
} g_algs [] =
{
    {TPM_ALG_SHA1, "TPM_ALG_SHA1"},
    {TPM_ALG_SHA256, "TPM_ALG_SHA256"},
    {TPM_ALG_SHA384, "TPM_ALG_SHA384"},
    {TPM_ALG_SHA512, "TPM_ALG_SHA512"},
    {TPM_ALG_SM3_256, "TPM_ALG_SM3_256"},
    {TPM_ALG_NULL, "TPM_ALG_NULL"}
};

int findAlgorithm(TPMI_ALG_HASH algId)
{
    for( int i = 0; g_algs[i].alg != TPM_ALG_NULL; i++ )
        if( g_algs[i].alg == algId )
            return i;

    return -1;
}

int showSpPcrValues(TPMI_ALG_HASH algId)
{
    UINT32 pcrId = 0;
    UINT32 rval;
    TPML_PCR_SELECTION  pcrSelectionIn;
    UINT32 pcrUpdateCounter;
    TPML_DIGEST pcrValues;
    TPML_PCR_SELECTION pcrSelectionOut;

    int i = findAlgorithm(algId);
    if ( i < 0 )
    {
        printf( "Unsupported Bank/Algorithm: 0x%04x\n", algId);
        return -1;
    }

    printf( "\nBank/Algorithm: %s(0x%04x)\n", g_algs[i].desc, g_algs[i].alg);

    for(pcrId = 0; pcrId < 24; pcrId++)
    {
        pcrSelectionIn.count = 1;
        pcrSelectionIn.pcrSelections[0].hash = algId;
        pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;

        pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
        pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
        pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;

        SET_PCR_SELECT_BIT( pcrSelectionIn.pcrSelections[0], pcrId );

        memset(&pcrValues, 0, sizeof(TPML_DIGEST));
        rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues, 0 );

        if(rval != TPM_RC_SUCCESS )
        {
            printf("This bank can not be read, tpm error 0x%0x\n\n", rval);
            return -2;
        }

        printf("PCR_%02d:", pcrId);
        for(int i = 0; i < pcrValues.digests[0].t.size; i++)
            printf(" %02x", pcrValues.digests[0].t.buffer[i]);
        printf("\n");

        if(fp != NULL &&
           fwrite(&pcrValues.digests[0].t.buffer[0],
                  pcrValues.digests[0].t.size, 1, fp) != 1)
        {
            printf("write to file %s failed!\n", outFilePath);
            return -3;
        }
    }
    return 0;
}

void showAllPcrValues()
{
    printf( "\nShow all PCR banks:\n" );

    for( int i = 0; g_algs[i].alg != TPM_ALG_NULL; i++ )
        showSpPcrValues(g_algs[i].alg);
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "-h, --help                Display command tool usage info;\n"
            "-v, --version             Display command tool version info;\n"
            "-g, --algorithim <hexAlg>     The algorithm id, optional\n"
            "-o, --output  <filename>      The file to hold the PCR values in binary format, optional\n"
            "-p, --port    <port number>   The Port number, default is %d, optional\n"
            "-d, --debugLevel <0|1|2|3>    The level of debug message, default is 0, optional\n"
                "\t0 (high level test results)\n"
                "\t1 (test app send/receive byte streams)\n"
                "\t2 (resource manager send/receive byte streams)\n"
                "\t3 (resource manager tables)\n"
            "\n\tExample:\n"
            "display usage:   %s -h\n"
            "display version: %s -v\n"
            "display all PCR values:  %s\n"
            "display the PCR values with specified bank:    \n"
            "   %s -g 0x04\n"
            , name, DEFAULT_RESMGR_TPM_PORT, name, name, name, name );
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvg:p:d:o:";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
        {"version",0,NULL,'v'},
        {"algorithm",1,NULL,'g'},
        {"output",1,NULL,'o'},
        {"port",1,NULL,'p'},
        {"debugLevel",1,NULL,'d'},
        {0,0,0,0}
    };

    TPMI_ALG_HASH algorithmId;

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        o_flag = 0,
        g_flag = 0;

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
        case 'g':
            if(getSizeUint16Hex(optarg,&algorithmId) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -1;
                break;
            }
            g_flag = 1;
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
            //          case 0:
            //              break;
        case ':':
            //              printf("Argument %c needs a value!\n",optopt);
            returnVal = -5;
            break;
        case '?':
            //              printf("Unknown Argument: %c\n",optopt);
            returnVal = -6;
            break;
            //default:
            //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag;

    if(o_flag)
    {
        fp = fopen(outFilePath,"w+");
        if(NULL == fp)
        {
            printf("OutFile: %s Can Not Be Created !\n",outFilePath);
            return -7;
        }
    }

    if(flagCnt == 1)
    {
        //if(argc == 2)
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
            return 0;
        }
    }
    else if(flagCnt == 0)
    {
        prepareTest(hostName, port, debugLevel);

        if(g_flag)
            returnVal = showSpPcrValues(algorithmId);
        else
            showAllPcrValues();

        finishTest();

        if(fp)
            fclose(fp);
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
