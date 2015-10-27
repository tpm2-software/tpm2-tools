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

int hash(TPMI_RH_HIERARCHY hierarchyValue, TPM2B_MAX_BUFFER *data, TPMI_ALG_HASH halg, const char *outHashFilePath, const char *outTicketFilePath)
{
    UINT32 rval;

    TPM2B_DIGEST outHash;
    TPMT_TK_HASHCHECK validation;

    rval = Tss2_Sys_Hash(sysContext, 0, data, halg, hierarchyValue, &outHash, &validation, 0);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......TPM2_Hash Error. TPM Error:0x%x......\n", rval);
        return -1;
    }
    printf("\ntpm2_hash succ.\n\n");

    printf("\nhash value(hex type): ");
    for(UINT16 i = 0; i < outHash.t.size; i++)
        printf("%02x ", outHash.t.buffer[i]);
    printf("\n");

    printf("\nvalidation value(hex type): ");
    for(INT16 j = 0; j < validation.digest.t.size; j++)
        printf("%02x ", validation.digest.t.buffer[j]);
    printf("\n");

    if(saveDataToFile(outHashFilePath, (UINT8 *)&outHash, sizeof(outHash)))
        return -2;
    if(saveDataToFile(outTicketFilePath, (UINT8 *)&validation, sizeof(validation)))
        return -3;

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-H, --hierarchy <e|o|p|n>   hierarchy to use for the ticket\n"
            "\te  TPM_RH_ENDORSEMENT\n"
            "\to  TPM_RH_OWNER\n"
            "\tp  TPM_RH_PLATFORM\n"
            "\tn  TPM_RH_NULL\n"
        "-g, --halg      <hexAlg>   algorithm for the hash being computed\n"
            "\t0x0004  TPM_ALG_SHA1\n"
            "\t0x000B  TPM_ALG_SHA256\n"
            "\t0x000C  TPM_ALG_SHA384\n"
            "\t0x000D  TPM_ALG_SHA512\n"
            "\t0x0012  TPM_ALG_SM3_256\n"
        "-I, --infile    <inputFilename>  file containning the data to be hashed\n"
        "-o, --outfile   <hashFilename>   file record the hash result\n"
        "-t, --ticket    <ticketFilename> file record the ticket\n"
        "-p, --port  <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3> The level of debug message, default is 0, optional\n"
            "\t0 (high level test results)\n"
            "\t1 (test app send/receive byte streams)\n"
            "\t2 (resource manager send/receive byte streams)\n"
            "\t3 (resource manager tables)\n"
        "\n"
        "Example:\n"
        "%s -H <e|o|p|n> -g 0x004 -I <inputFilename> -o <hashFilename> -t <ticketFilename> \n"
        , name, DEFAULT_RESMGR_TPM_PORT, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    TPMI_RH_HIERARCHY hierarchyValue;
    TPM2B_MAX_BUFFER data;
    TPMI_ALG_HASH  halg;
    char outHashFilePath[PATH_MAX] = {0};
    char outTicketFilePath[PATH_MAX] = {0};
    long fileSize = 0;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvH:g:I:o:t:p:d:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"Hierachy",1,NULL,'H'},
      {"halg",1,NULL,'g'},
      {"infile",1,NULL,'I'},
      {"outfile",1,NULL,'o'},
      {"ticket",1,NULL,'t'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        H_flag = 0,
        g_flag = 0,
        I_flag = 0,
        o_flag = 0,
        t_flag = 0;

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
        case 'g':
            if(getSizeUint16Hex(optarg,&halg) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -2;
                break;
            }
            printf("halg = 0x%4.4x\n", halg);
            g_flag = 1;
            break;
        case 'I':
            if( getFileSize(optarg, &fileSize) != 0)
            {
                returnVal = -3;
                break;
            }
            if(fileSize > MAX_DIGEST_BUFFER)
            {
                printf("Input data too long: %ld, should be less than %d bytes\n", fileSize, MAX_DIGEST_BUFFER);
                returnVal = -4;
                break;
            }
            data.t.size = fileSize;
            if(loadDataFromFile(optarg, data.t.buffer, &data.t.size) != 0)
            {
                returnVal = -5;
                break;
            }
            I_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outHashFilePath, optarg, sizeof(outHashFilePath));
            if(checkOutFile(outHashFilePath) != 0)
            {
                returnVal = -6;
                break;
            }
            o_flag = 1;
            break;
        case 't':
            safeStrNCpy(outTicketFilePath, optarg, sizeof(outTicketFilePath));
            if(checkOutFile(outTicketFilePath) != 0)
            {
                returnVal = -7;
                 break;
            }
            t_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -8;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -9;
            }
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
    flagCnt = h_flag + v_flag + H_flag + g_flag + I_flag + o_flag + t_flag;
    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -12;
        }
    }
    else if(flagCnt == 5 && h_flag != 1 && v_flag != 1)
    {
        prepareTest(hostName, port, debugLevel);

        returnVal = hash(hierarchyValue, &data, halg, outHashFilePath, outTicketFilePath);

        finishTest();

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
