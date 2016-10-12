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

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "common.h"
#include "sample.h"

int debugLevel = 0;
TPM_HANDLE persistentEKHandle;
TPM_HANDLE persistentAKHandle;
char endorsePasswd[sizeof(TPMU_HA)];
char akPasswd[sizeof(TPMU_HA)];
char ownerPasswd[sizeof(TPMU_HA)];
bool hexPasswd = false;
char outputFile[PATH_MAX];
char aknameFile[PATH_MAX];
UINT32 algorithmType = TPM_ALG_RSA;
UINT32 digestAlg = TPM_ALG_SHA256;
UINT32 signAlg = TPM_ALG_NULL;

int setRSASigningAlg(TPM2B_PUBLIC &inPublic)
{
    if (signAlg == TPM_ALG_NULL)
        signAlg = TPM_ALG_RSASSA;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = signAlg;
    switch(signAlg)
    {
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS:
        inPublic.t.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = digestAlg;
        break;
    default:
        printf("\n......The RSA signing algorithm type input(%4.4x) is not supported!......\n", signAlg);
        return -1;
    }

    return 0;
}

int setECCSigningAlg(TPM2B_PUBLIC &inPublic)
{
    if (signAlg == TPM_ALG_NULL)
        signAlg = TPM_ALG_ECDSA;
    inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = signAlg;
    switch(signAlg)
    {
    case TPM_ALG_ECDSA:
    case TPM_ALG_SM2:
    case TPM_ALG_ECSCHNORR:
    case TPM_ALG_ECDAA:
        inPublic.t.publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg = digestAlg;
    case TPM_ALG_NULL:
        break;
    default:
        printf("\n......The ECC signing algorithm type input(%4.4x) is not supported!......\n", signAlg);
        return -1;
    }

    return 0;
}

int setKeyedhashSigningAlg(TPM2B_PUBLIC &inPublic)
{
    if (signAlg == TPM_ALG_NULL)
        signAlg = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = signAlg;
    switch(signAlg)
    {
    case TPM_ALG_HMAC:
        inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = digestAlg;
    case TPM_ALG_NULL:
        break;
    default:
        printf("\n......The Keyedhash signing algorithm type input(%4.4x) is not supported!......\n", signAlg);
        return -1;
    }

    return 0;
}

int setKeyAlgorithm(UINT16 algorithm, TPM2B_SENSITIVE_CREATE &inSensitive, TPM2B_PUBLIC &inPublic)
{
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    // First clear attributes bit field.
    *(UINT32 *)&(inPublic.t.publicArea.objectAttributes) = 0;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.sign = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;

    inPublic.t.publicArea.type = algorithm;

    switch(algorithm)
    {
    case TPM_ALG_RSA:
        inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_NULL;
        inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.t.publicArea.unique.rsa.t.size = 0;
        if(setRSASigningAlg(inPublic))
           return -1;
        break;
    case TPM_ALG_ECC:
        inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic.t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_NULL;
        inPublic.t.publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
        inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic.t.publicArea.unique.ecc.x.t.size = 0;
        inPublic.t.publicArea.unique.ecc.y.t.size = 0;
        if(setECCSigningAlg(inPublic))
           return -2;
        break;
    case TPM_ALG_KEYEDHASH:
        inPublic.t.publicArea.unique.keyedHash.t.size = 0;
        if(setKeyedhashSigningAlg(inPublic))
           return -3;
        break;
    case TPM_ALG_SYMCIPHER:
    default:
        printf("\n......The algorithm type input(%4.4x) is not supported!......\n", algorithm);
        return -4;
    }

    return 0;
}

int createAK()
{
    UINT32 rval = TPM_RC_SUCCESS;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_SENSITIVE_CREATE  inSensitive = { { sizeof(TPM2B_SENSITIVE_CREATE)-2, } };
    TPM2B_PUBLIC            inPublic = { { sizeof(TPM2B_PUBLIC)-2, } };
    TPM2B_DATA              outsideInfo = { { 0, } };
    TPML_PCR_SELECTION      creationPCR;

    TPM2B_NAME              name = { { sizeof(TPM2B_NAME)-2, } };

    TPM2B_PRIVATE           outPrivate = { { sizeof( TPM2B_PRIVATE ) - 2, } };
    TPM2B_PUBLIC            outPublic = { { 0, } };
    TPM2B_CREATION_DATA     creationData = { { 0, } };
    TPM2B_DIGEST            creationHash = { { sizeof(TPM2B_DIGEST)-2, } };
    TPMT_TK_CREATION        creationTicket = { 0, };

    TPM_HANDLE handle2048rsa = persistentEKHandle;
    TPM_HANDLE loadedSha1KeyHandle;

    SESSION *session;
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = { { 0, } };
    TPM2B_NONCE         nonceCaller = { { 0, } };
    TPMT_SYM_DEF symmetric;

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    sessionsData.cmdAuthsCount = 1;
    sessionsDataOut.rspAuthsCount = 1;

    // set the object Auth value
    inSensitive.t.sensitive.userAuth.t.size = 0;
    if (strlen(akPasswd) > 0 && !hexPasswd)
    {
        inSensitive.t.sensitive.userAuth.t.size = strlen( akPasswd );
        memcpy( &( inSensitive.t.sensitive.userAuth.t.buffer[0] ), &( akPasswd[0] ), inSensitive.t.sensitive.userAuth.t.size );
    }
    else if (strlen(akPasswd) > 0 && hexPasswd)
    {
        inSensitive.t.sensitive.userAuth.t.size = sizeof(inSensitive.t.sensitive.userAuth) - 2;
        if (hex2ByteStructure(akPasswd,
                              &inSensitive.t.sensitive.userAuth.t.size,
                              inSensitive.t.sensitive.userAuth.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for akPasswd.\n");
            return -1;
        }
    }
    inSensitive.t.sensitive.data.t.size = 0;
    inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;

    creationPCR.count = 0;

    if( setKeyAlgorithm(algorithmType, inSensitive, inPublic) )
        return -1;

    sessionData.hmac.t.size = 0;
    if (strlen(endorsePasswd) > 0 && !hexPasswd)
    {
        sessionData.hmac.t.size = strlen(endorsePasswd);
        memcpy( &sessionData.hmac.t.buffer[0], endorsePasswd, sessionData.hmac.t.size );
    }
    else if (strlen(endorsePasswd) > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (hex2ByteStructure(endorsePasswd, &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for endorsePasswd.\n");
            return -1;
        }
    }

    symmetric.algorithm = TPM_ALG_NULL;

    rval = StartAuthSessionWithParams( &session, TPM_RH_NULL, 0, TPM_RH_NULL,
            0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......StartAuthSessionWithParams Error. TPM Error:0x%x......\n", rval);
        return -2;
    }
    printf("\nStartAuthSessionWithParams succ.......\n");

    rval = Tss2_Sys_PolicySecret(sysContext, TPM_RH_ENDORSEMENT, session->sessionHandle, &sessionsData, 0, 0, 0, 0, 0, 0, 0);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Tss2_Sys_PolicySecret Error. TPM Error:0x%x......\n", rval);
        return -3;
    }
    printf("\nTss2_Sys_PolicySecret succ.......\n");

    sessionData.sessionHandle = session->sessionHandle;
    sessionData.sessionAttributes.continueSession = 1;
    sessionData.hmac.t.size = 0;

    rval = Tss2_Sys_Create( sysContext, handle2048rsa, &sessionsData, &inSensitive, &inPublic,
            &outsideInfo, &creationPCR, &outPrivate, &outPublic, &creationData,
            &creationHash, &creationTicket, &sessionsDataOut );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......TPM2_Create Error. TPM Error:0x%x......\n", rval);
        return -4;
    }
    printf("\nTPM2_Create succ.......\n");

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext( sysContext, session->sessionHandle );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......TPM2_Sys_FlushContext Error. TPM Error:0x%x......\n", rval);
        return -5;
    }
    // And remove the session from sessions table.
    rval = EndAuthSession( session );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......EndAuthSession Error. TPM Error:0x%x......\n", rval);
        return -6;
    }

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.sessionAttributes.continueSession = 0;
    sessionData.hmac.t.size = 0;
    if (strlen(endorsePasswd) > 0 && !hexPasswd)
    {
        sessionData.hmac.t.size = strlen(endorsePasswd);
        memcpy( &sessionData.hmac.t.buffer[0], endorsePasswd, sessionData.hmac.t.size );
    }
    else if (strlen(endorsePasswd) > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (hex2ByteStructure(endorsePasswd, &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for endorsePasswd.\n");
            return -1;
        }
    }

    rval = StartAuthSessionWithParams( &session, TPM_RH_NULL, 0, TPM_RH_NULL,
            0, &nonceCaller, &encryptedSalt, TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256 );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......StartAuthSessionWithParams Error. TPM Error:0x%x......\n", rval);
        return -7;
    }
    printf("\nStartAuthSessionWithParams succ.......\n");

    rval = Tss2_Sys_PolicySecret(sysContext, TPM_RH_ENDORSEMENT, session->sessionHandle, &sessionsData, 0, 0, 0, 0, 0, 0, 0);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Tss2_Sys_PolicySecret Error. TPM Error:0x%x......\n", rval);
        return -8;
    }
    printf("\nTss2_Sys_PolicySecret succ.......\n");

    sessionData.sessionHandle = session->sessionHandle;
    sessionData.sessionAttributes.continueSession = 1;
    sessionData.hmac.t.size = 0;

    rval = Tss2_Sys_Load ( sysContext, handle2048rsa, &sessionsData, &outPrivate, &outPublic,
            &loadedSha1KeyHandle, &name, &sessionsDataOut);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......TPM2_Load Error. TPM Error:0x%x......\n", rval);
        return -9;
    }

    printf( "\nName of loaded key: \n" );
    PrintSizedBuffer( (TPM2B *)&name );
    printf("\n");
    printf( "\nLoaded key handle:  %8.8x\n", loadedSha1KeyHandle );

    // write name to ak.name file
    if( saveDataToFile(aknameFile, &name.t.name[0], name.t.size) )
    {
       printf("\n......Failed to save AK name into file(%s)......\n", aknameFile);
       return -10;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext( sysContext, session->sessionHandle );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......TPM2_Sys_FlushContext Error. TPM Error:0x%x......\n", rval);
        return -11;
    }

    // And remove the session from sessions table.
    rval = EndAuthSession( session );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......EndAuthSession Error. TPM Error:0x%x......\n", rval);
        return -12;
    }

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.sessionAttributes.continueSession = 0;
    sessionData.hmac.t.size = 0;
    // use the owner auth here.
    if (strlen(ownerPasswd) > 0 && !hexPasswd)
    {
        sessionData.hmac.t.size = strlen(ownerPasswd);
        memcpy( &sessionData.hmac.t.buffer[0], ownerPasswd, sessionData.hmac.t.size );
    }
    else if (strlen(ownerPasswd) > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (hex2ByteStructure(ownerPasswd, &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for ownerPasswd.\n");
            return -1;
        }
    }

    rval = Tss2_Sys_EvictControl(sysContext, TPM_RH_OWNER, loadedSha1KeyHandle, &sessionsData, persistentAKHandle, &sessionsDataOut);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......TPM2_EvictControl Error. TPM Error:0x%x......\n", rval);
        return -13;
    }
    printf("\nEvictControl: Make AK persistent succ.\n");

    rval = Tss2_Sys_FlushContext(sysContext, loadedSha1KeyHandle);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Flush transient AK error. TPM Error:0x%x......\n", rval);
        return -14;
    }
    printf("\nFlush transient AK succ.\n");

    // save ak public
    if( saveDataToFile(outputFile, (UINT8 *)&outPublic, sizeof(outPublic)) )
    {
        printf("\n......Failed to save AK pub key into file(%s)......\n", outputFile);
        return -15;
    }

    return 0;
}

void showHelp(const char *name)
{
    showVersion(name);
    printf("Usage: %s [-h/--help]\n"
           "   or: %s [-v/--version]\n"
           "   or: %s [-e/--endorsePasswd <password>] [-P/--akPasswd <password>] [-o/--ownerPasswd <password>]\n"
           "                     [-E/--ekHandle <hexHandle>] [-k/--akHandle <hexHandle>] [-g/--alg <hexAlg>] [-D/--digestAlg <hexAlg>]\n"
           "                     [-s/--signAlg <hexAlg>] [-f/--file <outputFile>] [-n/--akName <aknameFile>]\n"
           "   or: %s [-e/--endorsePasswd <password>] [-P/--akPasswd <password>] [-o/--ownerPasswd <password>]\n"
           "                     [-E/--ekHandle <hexHandle>] [-k/--akHandle <hexHandle>] [-g/--alg <hexAlg>] [-D/--digestAlg <hexAlg>]\n"
           "                     [-s/--signAlg <hexAlg>] [-f/--file <outputFile>] [-n/--akName <aknameFile>]\n"
           "                     [-X/--passwdInHex]\n"
           "                     [-p/--port <port>] [-d/--dbg <dbgLevel>]\n"
           "\nwhere:\n\n"
           "   -h/--help                       display this help and exit.\n"
           "   -v/--version                    display version information and exit.\n"
           "   -e/--endorsePasswd <password>   specifies current endorsement password (string,optional,default:NULL).\n"
           "   -P/--akPasswd    <password>     specifies the AK password when created (string,optional,default:NULL).\n"
           "   -o/--ownerPasswd <password>     specifies current owner password (string,optional,default:NULL).\n"
           "   -E/--ekHandle    <hexHandle>    specifies the handle of EK (hex).\n"
           "   -k/--akHandle    <hexHandle>    specifies the handle used to make AK persistent (hex).\n"
           "   -g/--alg         <hexAlg>       specifies the algorithm type of AK (default:0x01/TPM_ALG_RSA):\n"
           "                                      TPM_ALG_RSA             0x0001\n"
           "                                      TPM_ALG_KEYEDHASH       0x0008\n"
           "                                      TPM_ALG_ECC             0x0023\n"
           "   -D/--digestAlg  <hexAlg>         specifies the algorithm of digest.\n"
            "\t0x0004  TPM_ALG_SHA1\n"
            "\t0x000B  TPM_ALG_SHA256\n"
            "\t0x000C  TPM_ALG_SHA384\n"
            "\t0x000D  TPM_ALG_SHA512\n"
            "\t0x0012  TPM_ALG_SM3_256\n"
           "   -s/--signAlg    <hexAlg>         specifies the algorithm of sign.\n"
            "\t0x0005  TPM_ALG_HMAC\n"
            "\t0x0014  TPM_ALG_RSASSA\n"
            "\t0x0016  TPM_ALG_RSAPSS\n"
            "\t0x0018  TPM_ALG_ECDSA\n"
            "\t0x001A  TPM_ALG_ECDAA\n"
            "\t0x001B  TPM_ALG_SM2\n"
            "\t0x001C  TPM_ALG_ECSCHNORR\n"
           "   -f/--file       <outputFile>     specifies the file used to save the public portion of AK.\n"
           "   -n/--akName     <aknameFile>     specifies the file used to save the ak name.\n"
           "   -X/--passwdInHex                 passwords given by any options are hex format.\n"
           "   -p/--port       <port>           specifies the port number (default:%d).\n"
           "   -d/--dbg        <dbgLevel>       specifies level of debug messages:\n"
           "                                     0 (high level test results)\n"
           "                                     1 (test app send/receive byte streams)\n"
           "                                     2 (resource manager send/receive byte streams)\n"
           "                                     3 (resource manager tables)\n"
           "\nexample:\n"
           "   %s -e abc123 -P abc123 -o passwd -E 0x81010001 -k 0x81010002 -f ./ak.pub -n ./ak.name\n"
           "   %s -e 1a2b3c -P 123abc -o 1a1b1c -X -E 0x81010001 -k 0x81010002 -f ./ak.pub -n ./ak.name\n"
           , name, name, name, name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
    int opt;
    int returnVal = 0;


    struct option sOpts[] =
    {
        { "ownerPasswd", required_argument, NULL, 'o' },
        { "endorsePasswd", required_argument, NULL, 'e' },
        { "ekHandle"   , required_argument, NULL, 'E' },
        { "akHandle"   , required_argument, NULL, 'k' },
        { "alg"        , required_argument, NULL, 'g' },
        { "digestAlg"  , required_argument, NULL, 'D' },
        { "signAlg"    , required_argument, NULL, 's' },
        { "akPasswd"   , required_argument, NULL, 'P' },
        { "file"       , required_argument, NULL, 'f' },
        { "akName"     , required_argument, NULL, 'n' },
        { "passwdInHex", no_argument,       NULL, 'X' },
        { "port"       , required_argument, NULL, 'p' },
        { "dbg"        , required_argument, NULL, 'd' },
        { "help"       , no_argument,       NULL, 'h' },
        { "version"    , no_argument,       NULL, 'v' },
        { NULL         , no_argument,       NULL,  0  },
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

    while ( ( opt = getopt_long( argc, argv, "o:E:e:k:g:D:s:P:f:n:Xp:d:hv", sOpts, NULL ) ) != -1 )
    {
        switch ( opt ) {
        case 'h':
        case '?':
            showHelp(argv[0]);
            return 0;
        case 'v':
            showVersion(argv[0]);
            return 0;

        case 'E':
            if( getSizeUint32Hex(optarg, &persistentEKHandle) )
            {
                printf("\nPlease input the persistent EK handle(hex) in correct format.\n");
                return -2;
            }
            break;

        case 'k':
            if( getSizeUint32Hex(optarg, &persistentAKHandle) )
            {
                printf("\nPlease input the persistent handle used to make AK persistent(hex) in correct format.\n");
                return -3;
            }
            break;

        case 'g':
            if( getSizeUint32Hex(optarg, &algorithmType) )
            {
                printf("\nPlease input the algorithm type in correct format.\n");
                return -4;
            }
            break;

        case 'D':
            if( getSizeUint32Hex(optarg, &digestAlg) )
            {
                printf("\nPlease input the digest algorithm in correct format.\n");
                return -5;
            }
            break;

        case 's':
            if( getSizeUint32Hex(optarg, &signAlg) )
            {
                printf("\nPlease input the signing algorithm in correct format.\n");
                return -6;
            }
            break;

        case 'o':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the owner password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -7;
            }
            safeStrNCpy(ownerPasswd, optarg, sizeof(ownerPasswd));
            break;

        case 'e':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the endorsement password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -8;
            }
            safeStrNCpy(endorsePasswd, optarg, sizeof(endorsePasswd));
            break;

        case 'P':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input the AK password(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -9;
            }
            safeStrNCpy(akPasswd, optarg, sizeof(akPasswd));
            break;

        case 'f':
            if( optarg == NULL )
            {
                printf("\nPlease input the file used to save the pub ek.\n");
                return -10;
            }
            safeStrNCpy(outputFile, optarg, sizeof(outputFile));
            break;

        case 'n':
            if( optarg == NULL )
            {
                printf("\nPlease input the file used to save ak name.\n");
                return -11;
            }
            safeStrNCpy(aknameFile, optarg, sizeof(aknameFile));
            break;
        case 'X':
            hexPasswd = true;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                return -12;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                return -13;
            }
            break;
        default:
            showHelp(argv[0]);
            return -14;
        }
    }

    prepareTest(hostName, port, debugLevel);

    returnVal = createAK();

    finishTest();

    if(returnVal)
        return -15;

    return 0;
}
