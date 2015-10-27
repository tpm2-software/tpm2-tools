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
TPM_HANDLE handle2048rsa;
//declaretion for read and write file
TPM2B_NAME objectName;
char outFilePath[PATH_MAX] = {0};
TPM2B_PUBLIC inPublic;
TPM2B_DIGEST inCredential;

int writeCrtSecToFile(const char *path,TPM2B_ID_OBJECT *credentialBlob, TPM2B_ENCRYPTED_SECRET *secret)
{
    FILE *fp = fopen(path,"w+");
    if(NULL == fp)
    {
        printf("OutFile: %s Can Not Be Created !\n",path);
        return -1;
    }
    else
    {
        if(fwrite(credentialBlob,sizeof(TPM2B_ID_OBJECT),1,fp) != 1)
        {
            fclose(fp);
            printf("OutFile: %s Write Data In Error!\n",path);
            return -2;
        }
        if(fwrite(secret, sizeof(TPM2B_ENCRYPTED_SECRET), 1, fp) != 1)
        {
            fclose(fp);
            printf("OutFile: %s Write Data In Error!\n",path);
            return -3;
        }
    }
    fclose(fp);
    return 0;
}

int makeCredential()
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_NAME              nameExt     = { { sizeof(TPM2B_NAME)-2, } };

    TPM2B_ID_OBJECT         credentialBlob = { { 0 }, };
    TPM2B_ENCRYPTED_SECRET  secret;

    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    rval = Tss2_Sys_LoadExternal(sysContext, 0, NULL , &inPublic,TPM_RH_NULL,&handle2048rsa, &nameExt, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......LoadExternal failed. TPM Error:0x%x......\n", rval);
        return -1;
    }
    printf("LoadExternal succ.\n");

    rval = Tss2_Sys_MakeCredential(sysContext, handle2048rsa, 0, &inCredential, &objectName,&credentialBlob, &secret, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......MakeCredential failed. TPM Error:0x%x......\n", rval);
        return -2;
    }
    printf("MakeCredential succ.\n");

    rval = Tss2_Sys_FlushContext(sysContext, handle2048rsa);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Flush loaded key failed. TPM Error:0x%x......\n", rval);
        return -3;
    }
    printf("Flush loaded key succ.\n");

    if(writeCrtSecToFile(outFilePath,&credentialBlob,&secret))
        return -4;
    printf("OutFile: %s completed!\n\n",outFilePath);

    return 0;
}

void showHelp(const char *name)
{
    printf("%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-e, --encKey<keyFile>    A tpm Public Key which was used to wrap the seed\n"
        "-s, --sec   <secFile>    The secret which will be protected by the key derived from the random seed\n"
        "-n, --name  <hexString>  The name of the key for which certificate is to be created\n"
        "-o, --outFile<filePath>  output file path, recording the two structures output by tpm2_makecredential function\n"
//      "-i, --ip <simulator IP>  The IP address of simulator, optional\n"
        "-p, --port<port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel<0|1|2|3> The level of debug message, default is 0, optional\n"
        "\t0 (high level test results)\n"
        "\t1 (test app send/receive byte streams)\n"
        "\t2 (resource manager send/receive byte streams)\n"
        "\t3 (resource manager tables)\n"
        "\n"
        "Example:\n"
        "%s -e <keyFile> -s <secFile> -n <hexString> -o <outFile>\n"
        , name, DEFAULT_RESMGR_TPM_PORT, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
    UINT16 size;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hve:s:n:o:p:d:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"encKey",1,NULL,'e'},
      {"sec",1,NULL,'s'},
      {"name",1,NULL,'n'},
      {"outFile",1,NULL,'o'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        e_flag = 0,
        s_flag = 0,
        n_flag = 0,
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
        case 'e':
            size = sizeof(inPublic);
            if(loadDataFromFile(optarg, (UINT8 *)&inPublic, &size) != 0)
            {
                returnVal = -1;
                break;
            }
            e_flag = 1;
            break;
        case 's':
            inCredential.t.size = sizeof(inCredential) - 2;
            if(loadDataFromFile(optarg, inCredential.t.buffer, &inCredential.t.size) != 0)
            {
                returnVal = -2;
                break;
            }
            s_flag = 1;
            break;
        case 'n':
            objectName.t.size = sizeof(objectName) - 2;
            if(hex2ByteStructure(optarg,&objectName.t.size,objectName.t.name) != 0)
            {
                returnVal = -3;
                break;
            }
            n_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -4;
                break;
            }
            o_flag = 1;
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

    flagCnt = h_flag + v_flag + e_flag + s_flag + n_flag + o_flag;
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
    else if(flagCnt == 4 && h_flag != 1 && v_flag != 1)
    {
        prepareTest(hostName, port, debugLevel);

        returnVal = makeCredential();

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
