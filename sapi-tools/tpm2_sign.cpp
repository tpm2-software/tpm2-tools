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

int getKeyType(TPMI_DH_OBJECT objectHandle, TPMI_ALG_PUBLIC *type)
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = {&sessionDataOut};
    TSS2_SYS_RSP_AUTHS sessionsDataOut = {1, &sessionDataOutArray[0]};

    TPM2B_PUBLIC outPublic;
    TPM2B_NAME   name;
    TPM2B_NAME   qualifiedName;

    outPublic.t.size = 0;
    name.t.size = 0;
    qualifiedName.t.size = 0;

    rval = Tss2_Sys_ReadPublic(sysContext, objectHandle, 0, &outPublic, &name, &qualifiedName, &sessionsDataOut);
    if(rval == TPM_RC_SUCCESS)
    {
        *type = outPublic.t.publicArea.type;
        return 0;
    }
    return -1;
}

int setScheme(TPMI_DH_OBJECT keyHandle, TPMI_ALG_HASH halg, TPMT_SIG_SCHEME *inScheme)
{
    TPM_ALG_ID type;

    if(getKeyType(keyHandle, &type))
        return -1;

    printf("\nkeyType: 0x%04x\n", type);

    switch(type)
    {
    case TPM_ALG_RSA:
        inScheme->scheme = TPM_ALG_RSASSA;
        inScheme->details.rsassa.hashAlg = halg;
        break;
    case TPM_ALG_KEYEDHASH:
        inScheme->scheme = TPM_ALG_HMAC;
        inScheme->details.hmac.hashAlg = halg;
        break;
    case TPM_ALG_ECC:
        inScheme->scheme = TPM_ALG_ECDSA;
        inScheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM_ALG_SYMCIPHER:
    default:
        return -2;
    }

    return 0;
}

int sign(TPMI_DH_OBJECT keyHandle, TPMI_ALG_HASH halg, BYTE *msg, UINT16 length, TPMT_TK_HASHCHECK *validation, const char *outFilePath)
{
    UINT32 rval;
    TPM2B_DIGEST digest;
    TPMT_SIG_SCHEME inScheme;
    TPMT_SIGNATURE signature;

    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    if(computeDataHash(msg, length, halg, &digest))
    {
        printf("Compute message hash failed !\n");
        return -1;
    }

    printf("\ndigest(hex type):\n ");
    for(UINT16 i = 0; i < digest.t.size; i++)
         printf("%02x ", digest.t.buffer[i]);
    printf("\n");

    if(setScheme(keyHandle, halg, &inScheme))
    {
        printf("No suitable signing scheme!\n");
        return -2;
    }

    rval = Tss2_Sys_Sign(sysContext, keyHandle, &sessionsData, &digest, &inScheme, validation, &signature, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("tpm2_sign failed, error code: 0x%x\n", rval);
        return -3;
    }
    printf("\ntpm2_sign succ.\n");

    if(saveDataToFile(outFilePath, (UINT8 *)&signature, sizeof(signature)))
    {
        printf("failed to save signature into %s\n", outFilePath);
        return -4;
    }

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-k, --keyHandle<hexHandle>  Handle of key that will perform signing\n"
        "-c, --keyContext <filename>  filename of the key context used for the operation\n"
        "-P, --pwdk     <password>   the password of key, optional\n"
        "-g, --halg     <hexAlg>     the hash algorithm used to digest the message \n"
        "\t0x0004  TPM_ALG_SHA1\n"
        "\t0x000B  TPM_ALG_SHA256\n"
        "\t0x000C  TPM_ALG_SHA384\n"
        "\t0x000D  TPM_ALG_SHA512\n"
        "\t0x0012  TPM_ALG_SM3_256\n"
        "-m, --msg      <filePath>   the message file, containning the content to be digested\n"
        "-t, --ticket   <filePath>   the ticket file, containning the validation structure, optional\n"
        "-s, --sig      <filePath>   the signature file, record the signature structure\n"
        "-p, --port   <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3>  The level of debug message, default is 0, optional\n"
        "\t0 (high level test results)\n"
        "\t1 (test app send/receive byte streams)\n"
        "\t2 (resource manager send/receive byte streams)\n"
        "\t3 (resource manager tables)\n"
    "\n"
        "Example:\n"
        "%s -k 0x81010001 -P abc123 -g 0x000B -m <filePath> -s <filePath> -t <filePath>\n"
        "%s -k 0x81010001 -g 0x00B -m <filePath> -s <filePath>\n\n"// -i <simulator IP>\n\n",DEFAULT_TPM_PORT);
        ,name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    TPMI_DH_OBJECT keyHandle;
    BYTE *msg = NULL;
    UINT16 length = 0;
    UINT16 size = 0;
    long fileSize = 0;

    TPMT_TK_HASHCHECK validation;
    TPMI_ALG_HASH halg;
    char outFilePath[PATH_MAX] = {0};
    char inMsgFileName[PATH_MAX] = {0};
    char *contextKeyFile = NULL;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvk:P:g:m:t:s:p:d:c:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"keyHandle",1,NULL,'k'},
      {"pwdk",1,NULL,'P'},
      {"halg",1,NULL,'g'},
      {"msg",1,NULL,'m'},
      {"sig",1,NULL,'s'},
      {"ticket",1,NULL,'t'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {"keyContext",1,NULL,'c'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        k_flag = 0,
        P_flag = 0,
        g_flag = 0,
        m_flag = 0,
        t_flag = 0,
        c_flag = 0,
        s_flag = 0;

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
        case 'k':
            if(getSizeUint32Hex(optarg,&keyHandle) != 0)
            {
                returnVal = -1;
                break;
            }
            k_flag = 1;
            break;
        case 'P':
            sessionData.hmac.t.size = sizeof(sessionData.hmac.t) - 2;
            if(str2ByteStructure(optarg,&sessionData.hmac.t.size,sessionData.hmac.t.buffer) != 0)
            {
                returnVal = -2;
                break;
            }
            P_flag = 1;
            break;
        case 'g':
            if(getSizeUint16Hex(optarg,&halg) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -3;
                break;
            }
            printf("halg = 0x%4.4x\n", halg);
            g_flag = 1;
            break;
        case 'm':
            safeStrNCpy(inMsgFileName, optarg, sizeof(inMsgFileName));
            m_flag = 1;
            break;
        case 't':
            size = sizeof(validation);
            if(loadDataFromFile(optarg, (UINT8 *)&validation, &size) != 0)
            {
                returnVal = -4;
                break;
            }
            t_flag = 1;
            break;
        case 's':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -5;
                break;
            }
            s_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -6;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -7;
            }
            break;
        case 'c':
            contextKeyFile = optarg;
            if(contextKeyFile == NULL || contextKeyFile[0] == '\0')
            {
                returnVal = -8;
                break;
            }
            printf("contextKeyFile = %s\n", contextKeyFile);
            c_flag = 1;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -9;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -10;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        goto end;

    if(m_flag)
    {
        if(getFileSize(inMsgFileName, &fileSize))
        {
            returnVal = -11;
            goto end;
        }
        if(fileSize == 0)
        {
            printf("the message file is empty !\n");
            returnVal = -12;
            goto end;
        }
        if(fileSize > 0xffff)
        {
            printf("the message file was too long !\n");
            returnVal = -13;
            goto end;
        }
        msg = (BYTE*)malloc(fileSize);
        if(msg == NULL)
        {
            returnVal = -14;
            goto end;
        }
        memset(msg, 0, fileSize);

        length = fileSize;
        if(loadDataFromFile(inMsgFileName, msg, &length) != 0)
        {
            returnVal = -15;
            goto end;
        }
#if 0
        printf("\nmsg length: %d\n",length);
        printf("msg content: ");
        for(int i = 0; i < length; i++)
        {
            printf("%02x ", msg[i]);
        }
        printf("\n");
        return -1;
#endif
    }

    if(P_flag == 0)
        sessionData.hmac.t.size = 0;
    if(t_flag == 0)
    {
        validation.tag = TPM_ST_HASHCHECK;
        validation.hierarchy = TPM_RH_NULL;
        validation.digest.t.size = 0;
    }

    flagCnt = h_flag + v_flag + k_flag + g_flag + m_flag + s_flag + c_flag;

    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            returnVal = -16;
        }
    }
    else if((flagCnt == 4) && (k_flag == 1 || c_flag == 1) && (g_flag == 1) && (m_flag == 1) && (s_flag == 1))
    {
        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &keyHandle, contextKeyFile);
        if(returnVal == 0)
            returnVal = sign(keyHandle, halg, msg, length, &validation, outFilePath);

        finishTest();

        if(returnVal)
            returnVal = -17;
    }
    else
    {
        showArgMismatch(argv[0]);
        returnVal = -18;
    }

end:
    if(msg)
        free(msg);
    return returnVal;
}
