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
TPMS_AUTH_COMMAND cmdAuth, cmdAuth2;

int getKeyType(TPMI_DH_OBJECT objectHandle, TPMI_ALG_PUBLIC *type)
{
    TPM_RC rval;
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

int certify( TPMI_DH_OBJECT objectHandle, TPMI_DH_OBJECT keyHandle, TPMI_ALG_HASH  halg, const char *attestFilePath, const char *sigFilePath)
{
    TPM_RC rval;
    TPM2B_DATA qualifyingData;
    UINT8 qualDataString[] = { 0x00, 0xff, 0x55,0xaa };
    TPMT_SIG_SCHEME inScheme;
    TPM2B_ATTEST certifyInfo;
    TPMT_SIGNATURE signature;

    TPMS_AUTH_COMMAND *cmdSessionArray[2] = { &cmdAuth, &cmdAuth2 };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 2, &cmdSessionArray[0] };
    TPMS_AUTH_RESPONSE sessionDataOut1, sessionDataOut2;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[2] = {&sessionDataOut1, &sessionDataOut2};
    TSS2_SYS_RSP_AUTHS sessionsDataOut = {2, &sessionDataOutArray[0]};

    printf("\nCERTIFY TESTS:\n");

    cmdAuth.sessionHandle = TPM_RS_PW;
    cmdAuth2.sessionHandle = TPM_RS_PW;
    *((UINT8 *)((void *)&cmdAuth.sessionAttributes)) = 0;
    *((UINT8 *)((void *)&cmdAuth2.sessionAttributes)) = 0;

    qualifyingData.t.size = sizeof( qualDataString );
    memcpy( &( qualifyingData.t.buffer[0] ), qualDataString, sizeof( qualDataString ) );

    if ( setScheme(keyHandle, halg, &inScheme) )
    {
        printf("No suitable signing scheme!\n");
        return -1;
    }

    rval = Tss2_Sys_Certify( sysContext, objectHandle, keyHandle, &cmdAuthArray, &qualifyingData, &inScheme, &certifyInfo, &signature, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("TPM2_Certify failed. Error Code: 0x%x\n",rval);
        return -2;
    }
    printf("\nCertify succ.\n");

    if(saveDataToFile(attestFilePath, (UINT8 *)certifyInfo.t.attestationData, certifyInfo.t.size))
        return -3;
    printf("attestFile %s completed!\n",attestFilePath);

    if(saveDataToFile(sigFilePath, (UINT8 *)&signature, sizeof(signature)))
        return -4;
    printf("sigFile  %s completed!\n",sigFilePath);

    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
        "\n"
        "-h, --help               Display command tool usage info;\n"
        "-v, --version            Display command tool version info\n"
        "-H, --objHandle <hexHandle>  handle of the object to be certified\n"
        "-C, --objContext <filename>  filename of the object context to be certified\n"
        "-k, --keyHandle    <hexHandle>  handle of the key used to sign the attestation structure\n"
        "-c, --keyContext <filename>  filename of the key context used to sign the attestation structure\n"
        "-P, --pwdo         <string>     the object handle's password, optional\n"
        "-K, --pwdk         <string>     the keyHandle's password, optional\n"
        "-g, --halg         <hexAlg>     the hash algorithm used to digest the message\n"
        "\t0x0004  TPM_ALG_SHA1\n"
        "\t0x000B  TPM_ALG_SHA256\n"
        "\t0x000C  TPM_ALG_SHA384\n"
        "\t0x000D  TPM_ALG_SHA512\n"
        "\t0x0012  TPM_ALG_SM3_256\n"
        "-a, --attestFile   <fileName>   output file name, record the attestation structure\n"
        "-s, --sigFile      <fileName>   output file name, record the signature structure\n"
        "-p, --port   <port number>  The Port number, default is %d, optional\n"
        "-d, --debugLevel <0|1|2|3>  The level of debug message, default is 0, optional\n"
        "\t0 (high level test results)\n"
        "\t1 (test app send/receive byte streams)\n"
        "\t2 (resource manager send/receive byte streams)\n"
        "\t3 (resource manager tables)\n"
    "\n"
        "Example:\n"
        "%s -H 0x81010002 -k 0x81010001 -P 0x0011 -K 0x00FF -g 0x00B -a <fileName> -s <fileName>\n"
        "%s -H 0x81010002 -k 0x81010001 -g 0x00B -a <fileName> -s <fileName>\n\n"// -i <simulator IP>\n\n",DEFAULT_TPM_PORT);
        , name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char* argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;//DEFAULT_TPM_PORT;

    char attestFilePath[PATH_MAX] = {0};
    char sigFilePath[PATH_MAX] = {0};

    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_OBJECT keyHandle;
    TPMI_ALG_HASH  halg;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvH:k:P:K:g:a:s:p:d:C:c:";
    static struct option long_options[] = {
      {"help",0,NULL,'h'},
      {"version",0,NULL,'v'},
      {"objectHandle",1,NULL,'H'},
      {"keyHandle",1,NULL,'k'},
      {"pwdo",1,NULL,'P'},
      {"pwdk",1,NULL,'K'},
      {"halg",1,NULL,'g'},
      {"attestFile",1,NULL,'a'},
      {"sigFile",1,NULL,'s'},
      {"port",1,NULL,'p'},
      {"debugLevel",1,NULL,'d'},
      {"objContext",1,NULL,'C'},
      {"keyContext",1,NULL,'c'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        H_flag = 0,
        k_flag = 0,
        P_flag = 0,
        K_flag = 0,
        g_flag = 0,
        a_flag = 0,
        c_flag = 0,
        C_flag = 0,
        s_flag = 0;
    char *contextFile = NULL;
    char *contextKeyFile = NULL;

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
            if(getSizeUint32Hex(optarg,&objectHandle) != 0)
            {
                returnVal = -1;
                break;
            }
            H_flag = 1;
            break;
        case 'k':
            if(getSizeUint32Hex(optarg,&keyHandle) != 0)
            {
                returnVal = -2;
                break;
            }
            k_flag = 1;
            break;
        case 'P':
            cmdAuth.hmac.t.size = sizeof(cmdAuth.hmac.t) - 2;
            if(str2ByteStructure(optarg,&cmdAuth.hmac.t.size,cmdAuth.hmac.t.buffer) != 0)
            {
                returnVal = -3;
                break;
            }
            P_flag = 1;
            break;
        case 'K':
            cmdAuth2.hmac.t.size = sizeof(cmdAuth2.hmac.t) - 2;
            if(str2ByteStructure(optarg,&cmdAuth2.hmac.t.size,cmdAuth2.hmac.t.buffer) != 0)
            {
                returnVal = -4;
                break;
            }
            K_flag = 1;
            break;
        case 'g':
            if(getSizeUint16Hex(optarg,&halg) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -5;
                break;
            }
            printf("halg = 0x%4.4x\n", halg);
            g_flag = 1;
            break;
        case 'a':
            safeStrNCpy(attestFilePath, optarg, sizeof(attestFilePath));
            if(checkOutFile(attestFilePath) != 0)
            {
                returnVal = -6;
                break;
            }
            a_flag = 1;
            break;
        case 's':
            safeStrNCpy(sigFilePath, optarg, sizeof(sigFilePath));
            if(checkOutFile(sigFilePath) != 0)
            {
                returnVal = -7;
                break;
            }
            s_flag = 1;
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
        case 'c':
            contextKeyFile = optarg;
            if(contextKeyFile == NULL || contextKeyFile[0] == '\0')
            {
                returnVal = -10;
                break;
            }
            printf("contextKeyFile = %s\n", contextKeyFile);
            c_flag = 1;
            break;
        case 'C':
            contextFile = optarg;
            if(contextFile == NULL || contextFile[0] == '\0')
            {
                returnVal = -11;
                break;
            }
            printf("contextFile = %s\n", contextFile);
            C_flag = 1;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -12;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -13;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag + H_flag + k_flag + g_flag + a_flag + s_flag + c_flag + C_flag;
    if(P_flag == 0)
        cmdAuth.hmac.t.size = 0;
    if(K_flag == 0)
        cmdAuth2.hmac.t.size = 0;

    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -14;
        }
    }
    else if((flagCnt == 5) && (H_flag == 1 || C_flag) && (k_flag == 1 || c_flag) && (g_flag == 1) && (a_flag == 1) && (s_flag == 1))
    {
        prepareTest(hostName, port, debugLevel);

        if(C_flag)
            returnVal = loadTpmContextFromFile(sysContext, &objectHandle, contextFile);
        if(returnVal == 0 && c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &keyHandle, contextKeyFile);
        if(returnVal == 0)
            returnVal = certify(objectHandle, keyHandle, halg, attestFilePath, sigFilePath);

        finishTest();

        if(returnVal)
            return -15;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -16;
    }

    return 0;
}
