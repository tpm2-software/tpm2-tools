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
char outFilePath[PATH_MAX] = {0};
TPMI_DH_OBJECT activateHandle;
TPMI_DH_OBJECT keyHandle;

TPM2B_ID_OBJECT credentialBlob;
TPM2B_ENCRYPTED_SECRET secret;

TPMS_AUTH_COMMAND cmdAuth;
TPMS_AUTH_COMMAND cmdAuth2;

int readCrtSecFromFile(const char *path,TPM2B_ID_OBJECT *credentialBlob, TPM2B_ENCRYPTED_SECRET *secret)
{
    FILE *fp = fopen(path,"rb");
    if(NULL == fp)
    {
        printf("File: %s Not Found OR Access Error !\n",path);
        return -1;
    }
    if(fread(credentialBlob,sizeof(TPM2B_ID_OBJECT),1,fp) != 1)
    {
        fclose(fp);
        printf("Read credentialBlob from file  %s Error!\n",path);
        return -2;
    }
    if(fread(secret,sizeof(TPM2B_ENCRYPTED_SECRET),1,fp)!= 1)
    {
        fclose(fp);
        printf("Read secret form file %s error !\n",path);
        return -3;
    }
    fclose(fp);

    return 0;

}

int activateCredential()
{
    UINT32 rval;
    TPM2B_DIGEST certInfoData;

    printf("\nACTIVATE CREDENTIAL TESTS:\n");

    cmdAuth.sessionHandle = TPM_RS_PW;
    cmdAuth2.sessionHandle = TPM_RS_PW;
    *((UINT8 *)((void *)&cmdAuth.sessionAttributes)) = 0;

    *((UINT8 *)((void *)&cmdAuth2.sessionAttributes)) = 0;

    TPMS_AUTH_COMMAND *cmdSessionArray[2] = { &cmdAuth, &cmdAuth2 };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 2, &cmdSessionArray[0] };

    rval = Tss2_Sys_ActivateCredential(sysContext,activateHandle ,keyHandle , &cmdAuthArray, &credentialBlob, &secret, &certInfoData, 0);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\n......ActivateCredential failed. TPM Error:0x%x......\n", rval);
        return -1;
    }
    printf("\nActivate Credential succ.\n");

    printf("\nCertInfoData :\n");
    for (int k = 0; k<certInfoData.t.size; k++)
    {
        printf("0x%.2x ", certInfoData.t.buffer[k]);
    }
    printf("\n\n");

    if(saveDataToFile(outFilePath, certInfoData.t.buffer, certInfoData.t.size) == 0)
        printf("OutFile %s completed!\n",outFilePath);
    else
        return -2;

    return 0;
}

void showHelp(const char *name)
{
    printf("%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-H, --handle   <hexHandle>  Handle of the object associated with the created certificate by CA\n"
        "-c, --context   <filename>  filename for handle context\n"
        "-k, --keyHandle<hexHandle>  Loaded key used to decrypt the the random seed\n"
        "-C, --keyContext<filename>  filename for keyHandle context\n"
        "-P, --Password    <string>  the handle's password, optional\n"
        "-K, --keyPassword <string>  the keyHandle's password, optional\n"

        "-f, --inFile   <filePath>   Input file path, containing the two structures needed by tpm2_activatecredential function\n"
        "-o, --outFile  <filePath>   Output file path, record the secret to decrypt the certificate\n"
        "-p, --port   <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3>  The level of debug message, default is 0, optional\n"
        "\t0 (high level test results)\n"
        "\t1 (test app send/receive byte streams)\n"
        "\t2 (resource manager send/receive byte streams)\n"
        "\t3 (resource manager tables)\n"
    "\n"
        "Example:\n"
        "%s -H 0x81010002 -k 0x81010001 -P 0x0011 -K 0x00FF -f <filePath> -o <filePath>\n"
        , name, DEFAULT_RESMGR_TPM_PORT, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT; //DEFAULT_TPM_PORT;
    char *contextFilePath = NULL;
    char *keyContextFilePath = NULL;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvH:c:k:C:P:K:f:o:p:d:";
    struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"handle",1,NULL,'H'},
      {"context",1,NULL,'c'},
      {"keyHandle",1,NULL,'k'},
      {"keyContext",1,NULL,'C'},
      {"Password",1,NULL,'P'},
      {"keyPassword",1,NULL,'K'},
      {"inFile",1,NULL,'f'},
      {"outFile",1,NULL,'o'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {0,0,0,0},
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        H_flag = 0,
        c_flag = 0,
        k_flag = 0,
        C_flag = 0,
        K_flag = 0,
        P_flag = 0,
        f_flag = 0,
        o_flag = 0;

    if(argc == 1)
    {
        showHelp(argv[0]);
        return 0;
    }

    cmdAuth.hmac.t.size = 0;
    cmdAuth2.hmac.t.size = 0;

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
            if(getSizeUint32Hex(optarg,&activateHandle) != 0)
            {
                returnVal = -1;
                break;
            }
            H_flag = 1;
            break;
        case 'c':
            contextFilePath = optarg;
            if(contextFilePath == NULL || contextFilePath[0] == '\0')
            {
                returnVal = -2;
                break;
            }
            printf("contextFile = %s\n", contextFilePath);
            c_flag = 1;
            break;
        case 'k':
            if(getSizeUint32Hex(optarg,&keyHandle) != 0)
            {
                returnVal = -3;
                break;
            }
            k_flag = 1;
            break;
        case 'C':
            keyContextFilePath = optarg;
            if(keyContextFilePath == NULL || keyContextFilePath[0] == '\0')
            {
                returnVal = -4;
                break;
            }
            printf("keyContextFile = %s\n", keyContextFilePath);
            C_flag = 1;
            break;
        case 'P':
            cmdAuth.hmac.t.size = sizeof(cmdAuth.hmac.t) - 2;
            if(str2ByteStructure(optarg,&cmdAuth.hmac.t.size,cmdAuth.hmac.t.buffer) != 0)
            {
                returnVal = -5;
                break;
            }
            P_flag = 1;
            break;
        case 'K':
            cmdAuth2.hmac.t.size = sizeof(cmdAuth2.hmac.t) - 2;
            if(str2ByteStructure(optarg,&cmdAuth2.hmac.t.size,cmdAuth2.hmac.t.buffer) != 0)
            {
                returnVal = -6;
                break;
            }
            K_flag = 1;
            break;
        case 'f':
            if(readCrtSecFromFile(optarg,&credentialBlob,&secret) != 0)
            {
                returnVal = -7;
                break;
            }
            f_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
#if 0
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -1;
                break;
            }
#endif
            o_flag = 1;
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
    flagCnt = h_flag + v_flag + H_flag + c_flag + k_flag + C_flag + f_flag + o_flag;

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
    else if((flagCnt == 4) && (H_flag == 1 || c_flag == 1) && (k_flag == 1 || C_flag == 1) && (f_flag == 1) && (o_flag == 1))
    {
        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &activateHandle, contextFilePath);
        if(C_flag && returnVal == 0)
            returnVal = loadTpmContextFromFile(sysContext, &keyHandle, keyContextFilePath);
        if(returnVal == 0)
            returnVal = activateCredential();

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
