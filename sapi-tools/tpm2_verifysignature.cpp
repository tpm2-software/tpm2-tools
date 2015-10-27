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
BYTE *msg = NULL;
UINT16 msgLen = 0;
TPM2B_DIGEST msgHash;

int verifySignature(TPMI_DH_OBJECT keyHandle, int D_flag, TPMI_ALG_HASH halg, TPMT_SIGNATURE *signature, const char *outFilePath)
{
    UINT32 rval;
    TPMT_TK_VERIFIED validation;

    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    printf("\nTPM2_VerifySignature TESTS:\n");

    if(D_flag == 0)
    {
        if(computeDataHash(msg, msgLen, halg, &msgHash))
        {
            printf("Compute message hash failed !\n");
            return -1;
        }
        printf("\nVerifySignature: computing message hash succeeded!\n");
    }

    printf("\nmsgHash(hex type):\n ");
    for(UINT16 i = 0; i < msgHash.t.size; i++)
        printf("%02x ", msgHash.t.buffer[i]);
    printf("\n");

    rval = Tss2_Sys_VerifySignature(sysContext, keyHandle, NULL, &msgHash, signature, &validation, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("tpm2_verifysignature failed, error code: 0x%x\n", rval);
        return -2;
    }
    printf("\ntpm2_verifysignature succ.\n\n");

    if(saveDataToFile(outFilePath, (UINT8 *)&validation, sizeof(validation)))
    {
        printf("failed to save validation into %s\n", outFilePath);
        return -3;
    }

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-k, --keyHandle<hexHandle>  handle of public key that will be used in the validation\n"
        "-c, --keyContext <filename>  filename of the key context used for the operation\n"
        "-g, --halg     <hexAlg>     the hash algorithm used to digest the message \n"
        "\t0x0004  TPM_ALG_SHA1\n"
        "\t0x000B  TPM_ALG_SHA256\n"
        "\t0x000C  TPM_ALG_SHA384\n"
        "\t0x000D  TPM_ALG_SHA512\n"
        "\t0x0012  TPM_ALG_SM3_256\n"
        "-m, --msg      <filePath>   the input message file, containning the content to be digested\n"
        "-D, --digest   <filePath>   the input hash file, containning the hash of the message\n"
        "\tif this argument been chosed, the argument '-m(--msg)' and '-g(--halg)' is no need\n"
        "-s, --sig      <filePath>   the input signature file, containning the signature to be tested\n"
        "-r, --raw                   set the input signature file to raw type, default TPMT_SIGNATURE, optional\n"
        "-t, --ticket   <filePath>   the ticket file, record the validation structure\n"
        "-p, --port   <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3>  The level of debug message, default is 0, optional\n"
        "\t0 (high level test results)\n"
        "\t1 (test app send/receive byte streams)\n"
        "\t2 (resource manager send/receive byte streams)\n"
        "\t3 (resource manager tables)\n"
    "\n"
        "Example:\n"
        "%s -k 0x81010001 -g 0x000B -m <filePath> -s <filePath> -t <filePath>\n"
        "%s -k 0x81010001 -D <filePath> -s <filePath> -t <filePath>\n"
        ,name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    TPMI_DH_OBJECT keyHandle;
    long fileSize = 0;
    UINT16 size;

    TPMI_ALG_HASH halg = TPM_ALG_SHA256;
    TPMT_SIGNATURE  signature;
    char inSigFilePath[PATH_MAX] = {0};
    char outFilePath[PATH_MAX] = {0};
    char inMsgFilePath[PATH_MAX] = {0};
    char *contextKeyFile = NULL;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvk:g:m:D:rs:t:p:d:c:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"keyHandle",1,NULL,'k'},
      {"digest",1,NULL,'D'},
      {"halg",1,NULL,'g'},
      {"msg",1,NULL,'m'},
      {"raw",0,NULL,'r'},
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
        g_flag = 0,
        m_flag = 0,
        D_flag = 0,
        r_flag = 0,
        s_flag = 0,
        c_flag = 0,
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
        case 'k':
            if(getSizeUint32Hex(optarg,&keyHandle) != 0)
            {
                returnVal = -1;
                break;
            }
            k_flag = 1;
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
        case 'm':
            safeStrNCpy(inMsgFilePath, optarg, sizeof(inMsgFilePath));
            m_flag = 1;
            break;
        case 'D':
            size = sizeof(msgHash);
            if(loadDataFromFile(optarg, (UINT8 *)&msgHash, &size) != 0)
            {
                returnVal = -3;
                break;
            }
            D_flag = 1;
            break;
        case 'r':
            r_flag = 1;
            break;
        case 's':
            safeStrNCpy(inSigFilePath, optarg, sizeof(inSigFilePath));
            s_flag = 1;
            break;
        case 't':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -4;
                break;
            }
            t_flag = 1;
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
            contextKeyFile = optarg;
            if(contextKeyFile == NULL || contextKeyFile[0] == '\0')
            {
                returnVal = -7;
                break;
            }
            printf("contextKeyFile = %s\n", contextKeyFile);
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
        goto end;

    if(m_flag)
    {
        if(getFileSize(inMsgFilePath, &fileSize) != 0)
        {
            returnVal = -10;
            goto end;
        }
        if(fileSize == 0)
        {
            printf("the message file is empty !\n");
            returnVal = -11;
            goto end;
        }
        if(fileSize > 0xffff)
        {
            printf("the message file was too long !\n");
            returnVal = -12;
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
        msg = (BYTE*)malloc(fileSize);
        if(msg == NULL)
        {
            returnVal = -13;
            goto end;
        }
        memset(msg, 0, fileSize);

        msgLen = fileSize;
        if(loadDataFromFile(inMsgFilePath, msg, &msgLen) != 0)
        {
            returnVal = -14;
            goto end;
        }
    }

    if(D_flag == 1 && (m_flag == 1 || g_flag == 1))
    {
        showArgMismatch(argv[0]);
        returnVal = -15;
        goto end;
    }
    if(D_flag == 1)
    {
        printf("\nVerifySignature: using the input hash file!\n");
    }

    if(s_flag ==1)  //construct the signature
    {
        if(r_flag == 0)
        {
            UINT16 size = sizeof(signature);
            if(loadDataFromFile(inSigFilePath, (UINT8 *)&signature, &size))
            {
                returnVal = -16;
                goto end;
            }
            printf("VerifySignature: using the input signature file as sig structure!\n");
        }
        else
        {
            signature.sigAlg = TPM_ALG_RSASSA;
            signature.signature.rsassa.hash = halg;
            signature.signature.rsassa.sig.t.size = sizeof(signature.signature.rsassa.sig) - 2;
            if(loadDataFromFile(inSigFilePath, signature.signature.rsassa.sig.t.buffer,
                        &signature.signature.rsassa.sig.t.size))
            {
                returnVal = -17;
                goto end;
            }
            printf("VerifySignature: using the input signature file as raw data!\n");
        }
    }

    flagCnt = h_flag + v_flag + k_flag + g_flag + m_flag + D_flag + s_flag + t_flag + c_flag;

    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            returnVal = -18;
        }
    }
    else if(((flagCnt==4 && D_flag==1) || (flagCnt==5 && D_flag==0)) &&
            (h_flag==0  && v_flag==0) &&
            ((k_flag==1 || c_flag == 1) && s_flag==1 && t_flag==1) )
    {
        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &keyHandle, contextKeyFile);
        if(returnVal == 0)
            returnVal = verifySignature(keyHandle, D_flag, halg, &signature, outFilePath);

        finishTest();

        if(returnVal)
            returnVal = -19;
    }
    else
    {
        showArgMismatch(argv[0]);
        returnVal = -20;
    }

end:
    if(msg)
        free(msg);
    return returnVal;
}
