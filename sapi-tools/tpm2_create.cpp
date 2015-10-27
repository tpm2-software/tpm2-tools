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

TPMS_AUTH_COMMAND sessionData;
int debugLevel = 0;

int setAlg(TPMI_ALG_PUBLIC type,TPMI_ALG_HASH nameAlg,TPM2B_PUBLIC *inPublic, int I_flag)
{
    switch(nameAlg)
    {
    case TPM_ALG_SHA1:
    case TPM_ALG_SHA256:
    case TPM_ALG_SHA384:
    case TPM_ALG_SHA512:
    case TPM_ALG_SM3_256:
    case TPM_ALG_NULL:
        inPublic->t.publicArea.nameAlg = nameAlg;
        break;
    default:
        printf("nameAlg algrithm: 0x%0x not support !\n", nameAlg);
        return -1;
    }

    // First clear attributes bit field.
    *(UINT32 *)&(inPublic->t.publicArea.objectAttributes) = 0;
    inPublic->t.publicArea.objectAttributes.restricted = 0;
    inPublic->t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic->t.publicArea.objectAttributes.decrypt = 1;
    inPublic->t.publicArea.objectAttributes.sign = 1;
    inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic->t.publicArea.objectAttributes.fixedParent = 1;
    inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic->t.publicArea.type = type;
    switch(type)
    {
    case TPM_ALG_RSA:
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->t.publicArea.unique.rsa.t.size = 0;
        break;

    case TPM_ALG_KEYEDHASH:
        inPublic->t.publicArea.unique.keyedHash.t.size = 0;
        inPublic->t.publicArea.objectAttributes.decrypt = 0;
        if (I_flag)
        {
            // sealing
            inPublic->t.publicArea.objectAttributes.sign = 0;
            inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 0;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
        }
        else
        {
            // hmac
            inPublic->t.publicArea.objectAttributes.sign = 1;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM_ALG_ECC:
        inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.unique.ecc.x.t.size = 0;
        inPublic->t.publicArea.unique.ecc.y.t.size = 0;
        break;

    case TPM_ALG_SYMCIPHER:
        inPublic->t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        inPublic->t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        inPublic->t.publicArea.unique.sym.t.size = 0;
        break;

    default:
        printf("type algrithm: 0x%0x not support !\n",type);
        return -2;
    }
    return 0;
}

int create(TPMI_DH_OBJECT parentHandle, TPM2B_PUBLIC *inPublic, TPM2B_SENSITIVE_CREATE *inSensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, const char *opuFilePath, const char *oprFilePath, int o_flag, int O_flag, int I_flag, int A_flag, UINT32 objectAttributes)
{
    TPM_RC rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_DATA              outsideInfo = { { sizeof(TPM2B_DATA)-2, } };
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_PUBLIC            outPublic = { { sizeof(TPM2B_PUBLIC)-2, } };
    TPM2B_PRIVATE           outPrivate = { { sizeof(TPM2B_PRIVATE)-2, } };

    TPM2B_CREATION_DATA     creationData = { { sizeof(TPM2B_CREATION_DATA)-2, } };
    TPM2B_DIGEST            creationHash = { { sizeof(TPM2B_DIGEST)-2, } };
    TPMT_TK_CREATION        creationTicket = { 0, 0, { { sizeof(TPM2B_DIGEST)-2, } } };

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &sessionData;

    inSensitive->t.size = inSensitive->t.sensitive.userAuth.b.size + 2;

    if(setAlg(type, nameAlg, inPublic, I_flag))
        return -1;

    if(A_flag == 1)
        inPublic->t.publicArea.objectAttributes.val = objectAttributes;
    printf("ObjectAttribute: 0x%08X\n",inPublic->t.publicArea.objectAttributes.val);

    outsideInfo.t.size = 0;
    creationPCR.count = 0;
    outPublic.t.size = 0;
    creationData.t.size = sizeof(TPM2B_CREATION_DATA)-2;
    outPublic.t.publicArea.authPolicy.t.size = sizeof(TPM2B_DIGEST)-2;
    outPublic.t.publicArea.unique.keyedHash.t.size = sizeof(TPM2B_DIGEST)-2;

    rval = Tss2_Sys_Create(sysContext, parentHandle, &sessionsData, inSensitive, inPublic,
            &outsideInfo, &creationPCR, &outPrivate,&outPublic,&creationData, &creationHash,
            &creationTicket, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nCreate Object Failed ! ErrorCode: 0x%0x\n\n",rval);
        return -2;
    }
    printf("\nCreate Object Succeed !\n");

    if(o_flag == 1)
    {
        if(saveDataToFile(opuFilePath, (UINT8 *)&outPublic, sizeof(outPublic)))
            return -3;
    }
    if(O_flag == 1)
    {
        if(saveDataToFile(oprFilePath, (UINT8 *)&outPrivate, sizeof(outPrivate)))
            return -4;
    }

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help             Display command tool usage info;\n"
        "-v, --version          Display command tool version info\n"
        "-H, --parent <handle>  parent handle\n"
        "-c, --contextParent <filename> filename for parent context\n"
        "-P, --pwdp   <string>  password for parent key, optional\n"
        "-K, --pwdk   <string>  password for key, optional\n"
        "-g, --halg   <hexAlg>  algorithm used for computing the Name of the object\n"
            "\t0x0004  TPM_ALG_SHA1\n"
            "\t0x000B  TPM_ALG_SHA256\n"
            "\t0x000C  TPM_ALG_SHA384\n"
            "\t0x000D  TPM_ALG_SHA512\n"
            "\t0x0012  TPM_ALG_SM3_256\n"
        "-G, --kalg   <hexAlg>  algorithm associated with this object\n"
            "\t0x0001  TPM_ALG_RSA\n"
            "\t0x0008  TPM_ALG_KEYEDHASH\n"
            "\t0x0023  TPM_ALG_ECC\n"
            "\t0x0025  TPM_ALG_SYMCIPHER\n"
        "-A, --objectAttribute <hexAttributeDWord>  object attributes, optional\n"
        "-I, --inFile          <dataFileToBeSealed>  data file to be sealed, optional\n"
        "-L, --pol <policyFile>         the input policy file, optional\n"
        "-o, --opu <publicKeyFileName>  the output file which contains the public key, optional\n"
        "-O, --opr <privateKeyFileName> the output file which contains the private key, optional\n"

        "-p, --port  <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3> The level of debug message, default is 0, optional\n"
            "\t0 (high level test results)\n"
            "\t1 (test app send/receive byte streams)\n"
            "\t2 (resource manager send/receive byte streams)\n"
            "\t3 (resource manager tables)\n"
        "\n"
        "Example:\n"
        "%s -H 0x80000000 -P abc123 -K def456 -g 0x000B -G 0x0008 -I data.File -o opu.File\n"
        "%s -H 0x80000000 -g 0x000B -G 0x0008 -I data.File -o opu.File -O opr.File\n\n"// -i <simulator IP>\n\n",DEFAULT_TPM_PORT);
        ,name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char* argv[])
{

    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    TPM2B_SENSITIVE_CREATE  inSensitive;
    inSensitive.t.sensitive.data.t.size = 0;
    TPM2B_PUBLIC            inPublic;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMI_DH_OBJECT parentHandle;
    UINT32 objectAttributes = 0;
    char opuFilePath[PATH_MAX] = {0};
    char oprFilePath[PATH_MAX] = {0};
    char *contextParentFilePath = NULL;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvH:P:K:g:G:A:I:L:o:O:p:d:c:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"parent",1,NULL,'H'},
      {"pwdp",1,NULL,'P'},
      {"pwdk",1,NULL,'K'},
      {"halg",1,NULL,'g'},
      {"kalg",1,NULL,'G'},
      {"objectAttributes",1,NULL,'A'},
      {"inFile",1,NULL,'I'},
      {"policyFile",1,NULL,'L'},
      {"opu",1,NULL,'o'},
      {"opr",1,NULL,'O'},
      {"contextParent",1,NULL,'c'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {0,0,0,0}
    };


    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        H_flag = 0,
        P_flag = 0,
        K_flag = 0,
        g_flag = 0,
        G_flag = 0,
        A_flag = 0,
        I_flag = 0,
        L_flag = 0,
        o_flag = 0,
        c_flag = 0,
        O_flag = 0/*,
        f_flag = 0*/;
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
            if(getSizeUint32Hex(optarg,&parentHandle) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -1;
                break;
            }
            H_flag = 1;
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
        case 'K':
            inSensitive.t.sensitive.userAuth.t.size = sizeof(inSensitive.t.sensitive.userAuth.t) - 2;
            if(str2ByteStructure(optarg,&inSensitive.t.sensitive.userAuth.t.size, inSensitive.t.sensitive.userAuth.t.buffer) != 0)
            {
                returnVal = -3;
                break;
            }
            K_flag = 1;
            break;
        case 'g':
            if(getSizeUint16Hex(optarg,&nameAlg) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -4;
                break;
            }
            printf("nameAlg = 0x%4.4x\n", nameAlg);
            g_flag = 1;
            break;
        case 'G':
            if(getSizeUint16Hex(optarg,&type) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -5;
                break;
            }
            printf("type = 0x%4.4x\n", type);
            G_flag = 1;
            break;
        case 'A':
            if(getSizeUint32Hex(optarg,&objectAttributes) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -6;
                break;
            }
            A_flag = 1;//H_flag = 1;
            break;
        case 'I':
            inSensitive.t.sensitive.data.t.size = sizeof(inSensitive.t.sensitive.data) - 2;
            if(loadDataFromFile(optarg, inSensitive.t.sensitive.data.t.buffer, &inSensitive.t.sensitive.data.t.size) != 0)
            {
                returnVal = -7;
                break;
            }
            I_flag = 1;
            printf("inSensitive.t.sensitive.data.t.size = %d\n",inSensitive.t.sensitive.data.t.size);
            break;
        case 'L':
            inPublic.t.publicArea.authPolicy.t.size = sizeof(inPublic.t.publicArea.authPolicy) - 2;
            if(loadDataFromFile(optarg, inPublic.t.publicArea.authPolicy.t.buffer, &inPublic.t.publicArea.authPolicy.t.size) != 0)
            {
                returnVal = -8;
                break;
            }
            L_flag = 1;
            break;
        case 'o':
            safeStrNCpy(opuFilePath, optarg, sizeof(opuFilePath));
            if(checkOutFile(opuFilePath) != 0)
            {
                returnVal = -9;
                break;
            }
            o_flag = 1;
            break;
        case 'O':
            safeStrNCpy(oprFilePath, optarg, sizeof(oprFilePath));
            if(checkOutFile(oprFilePath) != 0)
            {
                returnVal = -10;
                break;
            }
            O_flag = 1;
            break;
        case 'c':
            contextParentFilePath = optarg;
            if(contextParentFilePath == NULL || contextParentFilePath[0] == '\0')
            {
                returnVal = -11;
                break;
            }
            printf("contextParentFile = %s\n", contextParentFilePath);
            c_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -12;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -13;
            }
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -14;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -15;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;

    if(P_flag == 0)
        sessionData.hmac.t.size = 0;
    if(I_flag == 0)
        inSensitive.t.sensitive.data.t.size = 0;
    if(K_flag == 0)
        inSensitive.t.sensitive.userAuth.t.size = 0;
    if(L_flag == 0)
        inPublic.t.publicArea.authPolicy.t.size = 0;

    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    flagCnt = h_flag + v_flag + H_flag + g_flag + G_flag + c_flag ;
    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -16;
        }
    }
    else if(flagCnt == 3 && (H_flag == 1 || c_flag == 1) && g_flag == 1 && G_flag == 1)
    {
        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &parentHandle, contextParentFilePath);
        if(returnVal == 0)
            returnVal = create(parentHandle, &inPublic, &inSensitive, type, nameAlg, opuFilePath, oprFilePath, o_flag, O_flag, I_flag, A_flag, objectAttributes);

        finishTest();

        if(returnVal)
            return -17;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -18;
    }
    return 0;
}
