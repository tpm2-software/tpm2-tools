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
char outputFile[PATH_MAX];
char ownerPasswd[sizeof(TPMU_HA)];
char endorsePasswd[sizeof(TPMU_HA)];
char ekPasswd[sizeof(TPMU_HA)];
TPM_HANDLE persistentHandle;
UINT32 algorithmType = TPM_ALG_RSA;

int setKeyAlgorithm(UINT16 algorithm, TPM2B_SENSITIVE_CREATE &inSensitive, TPM2B_PUBLIC &inPublic)
{
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    // First clear attributes bit field.
    *(UINT32 *)&(inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.sign = 0;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.type = algorithm;

    switch(algorithm)
    {
    case TPM_ALG_RSA:
        inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.t.publicArea.unique.rsa.t.size = 0;
        break;
    case TPM_ALG_KEYEDHASH:
        inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
        inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM_ALG_SHA256;
        inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM_ALG_KDF1_SP800_108;
        inPublic.t.publicArea.unique.keyedHash.t.size = 0;
        break;
    case TPM_ALG_ECC:
        inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        inPublic.t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        inPublic.t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_CFB;
        inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic.t.publicArea.unique.ecc.x.t.size = 0;
        inPublic.t.publicArea.unique.ecc.y.t.size = 0;
        break;
    case TPM_ALG_SYMCIPHER:
        inPublic.t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        inPublic.t.publicArea.parameters.symDetail.sym.keyBits.aes = 128;
        inPublic.t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        inPublic.t.publicArea.unique.sym.t.size = 0;
        break;
    default:
        printf("\n......The algorithm type input(%4.4x) is not supported!......\n", algorithm);
        return -1;
    }

    return 0;
}

int createEKHandle()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_SENSITIVE_CREATE  inSensitive = { { sizeof(TPM2B_SENSITIVE_CREATE)-2, } };
    TPM2B_PUBLIC            inPublic = { { sizeof(TPM2B_PUBLIC)-2, } };
    TPM2B_DATA              outsideInfo = { { sizeof(TPM2B_DATA)-2, } };
    TPML_PCR_SELECTION      creationPCR;

    TPM2B_NAME              name = { { sizeof(TPM2B_NAME)-2, } };

    TPM2B_PUBLIC            outPublic = { { sizeof(TPM2B_PUBLIC)-2, } };
    TPM2B_CREATION_DATA     creationData = { { sizeof(TPM2B_CREATION_DATA)-2, } };
    TPM2B_DIGEST            creationHash = { { sizeof(TPM2B_DIGEST)-2, } };
    TPMT_TK_CREATION        creationTicket = { 0, 0, { { sizeof(TPM2B_DIGEST)-2, } } };

    TPM_HANDLE handle2048ek;

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    // use enAuth in Tss2_Sys_CreatePrimary
    if( strlen( endorsePasswd ) > 0 )
    {
        sessionData.hmac.t.size = strlen( endorsePasswd );
        memcpy( &( sessionData.hmac.t.buffer[0] ), &( endorsePasswd[0] ), sessionData.hmac.t.size );
    }

    inSensitive.t.sensitive.userAuth.t.size = strlen( ekPasswd );
    if( strlen( ekPasswd ) > 0 )
    {
        memcpy( &( inSensitive.t.sensitive.userAuth.t.buffer[0] ), &( ekPasswd[0] ), inSensitive.t.sensitive.userAuth.t.size );
    }
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;

    if( setKeyAlgorithm(algorithmType, inSensitive, inPublic) )
        return -1;

    outsideInfo.t.size = 0;
    creationPCR.count = 0;
    outPublic.t.size = 0;
    creationData.t.size = sizeof(TPM2B_CREATION_DATA)-2;
    outPublic.t.publicArea.authPolicy.t.size = sizeof(TPM2B_DIGEST)-2;
    outPublic.t.publicArea.unique.keyedHash.t.size = sizeof(TPM2B_DIGEST)-2;

    /*To Create EK*/
    rval = Tss2_Sys_CreatePrimary(sysContext, TPM_RH_ENDORSEMENT, &sessionsData, &inSensitive, &inPublic,
        &outsideInfo, &creationPCR, &handle2048ek, &outPublic, &creationData, &creationHash,
        &creationTicket, &name, &sessionsDataOut);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......TPM2_CreatePrimary Error. TPM Error:0x%x......\n", rval);
        return -2;
    }
    printf("\nEK create succ.. Handle: 0x%8.8x\n", handle2048ek);

    // To make EK persistent, use own auth
    sessionData.hmac.t.size = strlen( ownerPasswd );
    if( strlen( ownerPasswd ) > 0 )
        memcpy( &( sessionData.hmac.t.buffer[0] ), &( ownerPasswd[0] ), sessionData.hmac.t.size );

    rval = Tss2_Sys_EvictControl(sysContext, TPM_RH_OWNER, handle2048ek, &sessionsData, persistentHandle, &sessionsDataOut);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......EvictControl:Make EK persistent Error. TPM Error:0x%x......\n", rval);
        return -3;
    }
    printf("EvictControl EK persistent succ.\n");

    rval = Tss2_Sys_FlushContext(sysContext, handle2048ek);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Flush transient EK failed. TPM Error:0x%x......\n", rval);
        return -4;
    }
    printf("Flush transient EK succ.\n");

    // save ek public
    if( saveDataToFile(outputFile, (UINT8 *)&outPublic, sizeof(outPublic)) )
    {
        printf("\n......Failed to save EK pub key into file(%s)......\n", outputFile);
        return -5;
    }

    return 0;
}

void showHelp(const char *name)
{
    showVersion(name);
    printf("Usage: %s [-h/--help]\n"
           "   or: %s [-v/--version]\n"
           "   or: %s [-e/--endorsePasswd <password>] [-o/--ownerPasswd <password>] [-P/--ekPasswd <password>]\n"
           "                     [-H/--handle <hexHandle>] [-g/--alg <hexAlg>] [-f/--file <outputFile>]\n"
           "   or: %s [-e/--endorsePasswd <password>] [-o/--ownerPasswd <password>] [-P/--ekPasswd <password>]\n"
           "                     [-H/--handle <hexHandle>] [-g/--alg <hexAlg>] [-f/--file <outputFile>]\n"
           "                     [-i/--ip <ipAddress>] [-p/--port <port>] [-d/--dbg <dbgLevel>]\n"
           "\nwhere:\n\n"
           "   -h/--help                       display this help and exit.\n"
           "   -v/--version                    display version information and exit.\n"
           "   -e/--endorsePasswd <password>   specifies current endorse password (string,optional,default:NULL).\n"
           "   -o/--ownerPasswd   <password>   specifies current owner password (string,optional,default:NULL).\n"
           "   -P/--ekPasswd      <password>   specifies the EK password when created (string,optional,default:NULL).\n"
           "   -H/--handle        <hexHandle>  specifies the handle used to make EK persistent (hex).\n"
           "   -g/--alg           <hexAlg>     specifies the algorithm type of EK (default:0x01/TPM_ALG_RSA).\n"
           "   -f/--file          <outputFile> specifies the file used to save the public portion of EK.\n"
           "   -p/--port          <port>       specifies the port number (optional,default:%d).\n"
           "   -d/--dbg           <dbgLevel>   specifies level of debug messages(optional,default:0):\n"
           "                                     0 (high level test results)\n"
           "                                     1 (test app send/receive byte streams)\n"
           "                                     2 (resource manager send/receive byte streams)\n"
           "                                     3 (resource manager tables)\n"
           "\nexample:\n"
           "   %s -e abc123 -o abc123 -P passwd -H 0x81010001 -g 0x01 -f ek.pub\n"
        , name, name, name, name, DEFAULT_RESMGR_TPM_PORT, name);
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
    int opt;
    int returnVal = 0;

    struct option sOpts[] =
    {
        { "endorsePasswd", required_argument, NULL, 'e' },
        { "ownerPasswd"  , required_argument, NULL, 'o' },
        { "handle"       , required_argument, NULL, 'H' },
        { "ekPasswd"     , required_argument, NULL, 'P' },
        { "alg"          , required_argument, NULL, 'g' },
        { "file"         , required_argument, NULL, 'f' },
        { "port"         , required_argument, NULL, 'p' },
        { "dbg"          , required_argument, NULL, 'd' },
        { "help"         , no_argument,       NULL, 'h' },
        { "version"      , no_argument,       NULL, 'v' },
        { NULL           , no_argument,       NULL,  0  },
    };

    if(argc == 1)
    {
        showHelp(argv[0]);
        return 0;
    }

    if( argc > (int)(2*sizeof(sOpts)/sizeof(struct option)) )
    {
        showArgMismatch(argv[0]);
        return -1;
    }

    while ( ( opt = getopt_long( argc, argv, "e:o:H:P:g:f:p:d:hv", sOpts, NULL ) ) != -1 )
    {
        switch ( opt ) {
        case 'h':
        case '?':
            showHelp(argv[0]);
            return 0;
        case 'v':
            showVersion(argv[0]);
            return 0;

        case 'H':
            if( getSizeUint32Hex(optarg, &persistentHandle) )
            {
                printf("\nPlease input the handle used to make EK persistent(hex) in correct format.\n");
                return -2;
            }
            break;

        case 'e':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the endorsement password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -3;
            }
            safeStrNCpy(endorsePasswd, optarg, sizeof(endorsePasswd));
            break;

        case 'o':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the owner password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -4;
            }
            safeStrNCpy(ownerPasswd, optarg, sizeof(ownerPasswd));
            break;

        case 'P':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the EK password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -5;
            }
            safeStrNCpy(ekPasswd, optarg, sizeof(ekPasswd));
            break;

        case 'g':
            if( getSizeUint32Hex(optarg, &algorithmType) )
            {
                printf("\nPlease input the algorithm type in correct format.\n");
                return -6;
            }
            break;

        case 'f':
            if( optarg == NULL )
            {
                printf("\nPlease input the file used to save the pub ek.\n");
                return -7;
            }
            safeStrNCpy(outputFile, optarg, sizeof(outputFile));
            break;

        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                return -8;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                return -9;
            }
            break;

        default:
            showHelp(argv[0]);
            return -10;
        }
    }

    prepareTest(hostName, port, debugLevel);

    returnVal = createEKHandle();

    finishTest();

    if( returnVal )
        return -11;

    return 0;
}

