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
#include <arpa/inet.h>

#include "tpm20.h"
#include "tpmsockets.h"
#include "common.h"

int debugLevel = 0;

typedef struct {
    int size;
    UINT32 id[24];
} PCR_LIST;
TPMS_AUTH_COMMAND sessionData;
char outFilePath[PATH_MAX];

void PrintBuffer( UINT8 *buffer, UINT32 size )
{
    UINT32 i;
    for( i = 0; i < size; i++ )
    {
        printf( "%2.2x", buffer[i] );
    }
    printf( "\n" );
}

void PrintSizedBuffer( TPM2B *sizedBuffer )
{
    int i;

    for( i = 0; i < sizedBuffer->size; i++ )
    {
        printf( "%2.2x ", sizedBuffer->buffer[i] );

        if( ( (i+1) % 16 ) == 0 )
        {
            printf( "\n" );
        }
    }
    printf( "\n" );
}

#if 0
void PrintTPM2B_ATTEST( TPM2B_ATTEST *attest )
{
    TPMS_ATTEST *s_att = (TPMS_ATTEST *)&attest->t.attestationData[0];

    printf( "ATTEST_2B:\n" );
    printf( "\tsize = 0x%4.4x\n", attest->t.size ); //already little endian
    printf( "\tattestationData(TPMS_ATTEST):\n" );
    printf( "\t\tmagic = 0x%8.8x\n", ntohl(s_att->magic) );//big endian
    printf( "\t\ttype  = 0x%4.4x\n", ntohs(s_att->type) );
    printf( "\t\tqualifiedSigner(NAME_2B):\n" );
    printf( "\t\t\tsize = 0x%4.4x\n", ntohs(s_att->qualifiedSigner.t.size) );
    printf( "\t\t\tname = " );
    PrintBuffer( s_att->qualifiedSigner.b.buffer, ntohs(s_att->qualifiedSigner.b.size) );
    s_att = (TPMS_ATTEST *)(((BYTE *)s_att) - sizeof(s_att->qualifiedSigner.t) + ntohs(s_att->qualifiedSigner.t.size) + 2);
    printf( "\t\textraData(DATA_2B):\n" );
    printf( "\t\t\tsize   = 0x%4.4x\n", ntohs(s_att->extraData.t.size) );
    printf( "\t\t\tbuffer = " );
    PrintBuffer( s_att->extraData.b.buffer, ntohs(s_att->extraData.b.size) );
    s_att = (TPMS_ATTEST *)(((BYTE *)s_att) - sizeof(s_att->extraData.t) + ntohs(s_att->extraData.t.size) + 2);
    printf( "\t\tclockInfo(TPMS_CLOCK_INFO):\n" );
    printf( "\t\t\tclock        = 0x%16.16lx\n", s_att->clockInfo.clock );
    printf( "\t\t\tresetCount   = 0x%8.8x\n", ntohl(s_att->clockInfo.resetCount) );
    printf( "\t\t\trestartCount = 0x%8.8x\n", ntohl(s_att->clockInfo.restartCount) );
    printf( "\t\t\tsafe         = 0x%2.2x\n", s_att->clockInfo.safe );

    s_att = (TPMS_ATTEST *)(((BYTE *)s_att) - 7);
    printf( "\t\tfirmwareVersion = 0x%16.16lx\n", s_att->firmwareVersion );
    printf( "\t\tattested(TPMS_QUOTE_INFO):\n" );
    printf( "\t\t\tpcrSelect(TPML_PCR_SELECTION):\n" );
    printf( "\t\t\t\tcount = 0x%8.8x\n", ntohl(s_att->attested.quote.pcrSelect.count) );
    for ( UINT32 i = 0; i < ntohl(s_att->attested.quote.pcrSelect.count); i++ )
    {
        TPMS_PCR_SELECTION *s = &s_att->attested.quote.pcrSelect.pcrSelections[i];
        printf( "\t\t\t\tpcrSelections[%d](TPMS_PCR_SELECTION):\n", i );
        printf( "\t\t\t\t\thash = 0x%4.4x\n", ntohs(s->hash) );
        printf( "\t\t\t\t\tsizeofSelect = 0x%2.2x\n", s->sizeofSelect );
        printf( "\t\t\t\t\tpcrSelect = " );
        PrintBuffer( s->pcrSelect, s->sizeofSelect );
    }
    s_att = (TPMS_ATTEST *)(((BYTE *)s_att) - sizeof(s_att->attested.quote.pcrSelect) + ntohl(s_att->attested.quote.pcrSelect.count) * sizeof(TPMS_PCR_SELECTION) + 4 );
    printf( "\t\t\tpcrDigest(DIGEST_2B):\n" );
    printf( "\t\t\t\tsize = 0x%4.4x\n", ntohs(s_att->attested.quote.pcrDigest.t.size) );
    printf( "\t\t\t\tbuffer = " );
    PrintBuffer( s_att->attested.quote.pcrDigest.b.buffer, ntohs(s_att->attested.quote.pcrDigest.b.size) );
}

void PrintTPMT_SIGNATURE( TPMT_SIGNATURE *sig )
{
    printf( "TPMT_SIGNATURE:\n" );
    printf( "\tsigAlg = 0x%4.4x\n", sig->sigAlg );
    printf( "\tsignature(TPMU_SIGNATURE):\n" );
    switch ( sig->sigAlg )
    {
        case TPM_ALG_RSASSA:
        case TPM_ALG_RSAPSS:
            printf( "\t\tTPMS_SIGNATURE_RSA:\n" );
            printf( "\t\t\thash = 0x%4.4x\n", sig->signature.rsassa.hash );
            printf( "\t\t\tsig(PUBLIC_KEY_RSA_2B):\n" );
            printf( "\t\t\t\tsize = 0x%4.4x\n", sig->signature.rsassa.sig.t.size );
            printf( "\t\t\t\tbuffer = " );
            PrintSizedBuffer( &sig->signature.rsassa.sig.b );
            break;
        case TPM_ALG_ECDSA:
        case TPM_ALG_ECDAA:
        case TPM_ALG_SM2:
        case TPM_ALG_ECSCHNORR:
            printf( "\t\tTPMS_SIGNATURE_ECC:\n" );
            printf( "\t\t\thash = 0x%4.4x\n", sig->signature.ecdsa.hash);
            printf( "\t\t\tsignatureR(TPM2B_ECC_PARAMETER):\n" );
            printf( "\t\t\t\tsize = 0x%4.4x\n", sig->signature.ecdsa.signatureR.t.size );
            printf( "\t\t\t\tbuffer = " );
            PrintSizedBuffer( &sig->signature.ecdsa.signatureR.b );
            printf( "\t\t\tsignatureS(TPM2B_ECC_PARAMETER):\n" );
            printf( "\t\t\t\tsize = 0x%4.4x\n", sig->signature.ecdsa.signatureS.t.size );
            printf( "\t\t\t\tbuffer = " );
            PrintSizedBuffer( &sig->signature.ecdsa.signatureS.b );
            break;
        case TPM_ALG_HMAC:
            printf( "\t\tTPMS_HA:\n" );
            printf( "\t\t\thashAlg = 0x%4.4x\n", sig->signature.hmac.hashAlg);
            printf( "\t\t\tdigest = " );
            UINT16 size = 0;
            switch ( sig->signature.hmac.hashAlg )
            {
                case TPM_ALG_SHA1:    size = SHA1_DIGEST_SIZE;    break;
                case TPM_ALG_SHA256:  size = SHA256_DIGEST_SIZE;  break;
                case TPM_ALG_SHA384:  size = SHA384_DIGEST_SIZE;  break;
                case TPM_ALG_SHA512:  size = SHA512_DIGEST_SIZE;  break;
                case TPM_ALG_SM3_256: size = SM3_256_DIGEST_SIZE; break;
            }
            PrintBuffer( (BYTE *)&sig->signature.hmac.digest, size );
            break;
    }
}
#endif

UINT16 calcSizeofTPM2B_ATTEST( TPM2B_ATTEST *attest )
{
    return 2 + attest->b.size;
}

UINT16  calcSizeofTPMT_SIGNATURE( TPMT_SIGNATURE *sig )
{
    UINT16 size = 2;
    switch ( sig->sigAlg )
    {
        case TPM_ALG_RSASSA:
        case TPM_ALG_RSAPSS:
            size += 2 + 2 + sig->signature.rsassa.sig.t.size;
            break;
        case TPM_ALG_ECDSA:
        case TPM_ALG_ECDAA:
        case TPM_ALG_SM2:
        case TPM_ALG_ECSCHNORR:
            size += 2 + 2*sizeof(TPM2B_ECC_PARAMETER);
            break;
        case TPM_ALG_HMAC:
            size += 2;
            switch ( sig->signature.hmac.hashAlg )
            {
                case TPM_ALG_SHA1:    size += SHA1_DIGEST_SIZE;    break;
                case TPM_ALG_SHA256:  size += SHA256_DIGEST_SIZE;  break;
                case TPM_ALG_SHA384:  size += SHA384_DIGEST_SIZE;  break;
                case TPM_ALG_SHA512:  size += SHA512_DIGEST_SIZE;  break;
                case TPM_ALG_SM3_256: size += SM3_256_DIGEST_SIZE; break;
                default: size = 0; break;
            }
            break;
        default:
            size = 0;
            break;
    }

    return size > sizeof(*sig) ? sizeof(*sig) : size;
}

int quote(TPM_HANDLE akHandle, PCR_LIST pcrList, TPMI_ALG_HASH algorithmId)
{
    UINT32 rval;
    TPM2B_DATA qualifyingData;
    UINT8 qualDataString[] = { 0x00, 0xff, 0x55, 0xaa };
    TPMT_SIG_SCHEME inScheme;
    TPML_PCR_SELECTION  pcrSelection;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;

    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    qualifyingData.t.size = sizeof( qualDataString );
    memcpy( &qualifyingData.t.buffer[0], qualDataString, sizeof( qualDataString ) );

    inScheme.scheme = TPM_ALG_NULL;

    pcrSelection.count = 1;
    pcrSelection.pcrSelections[0].hash = algorithmId;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;

    // Clear out PCR select bit field
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0;

    // Now set the PCR you want
    for(int l=0;l<pcrList.size; l++)
    {
        UINT32 pcrId = pcrList.id[l];
        pcrSelection.pcrSelections[0].pcrSelect[( pcrId/8 )] |= ( 1 << ( pcrId) % 8);
    }

    memset( (void *)&quoted, 0, sizeof(quoted) );
    memset( (void *)&signature, 0, sizeof(signature) );

    rval = Tss2_Sys_Quote(sysContext, akHandle, &sessionsData,
            &qualifyingData, &inScheme, &pcrSelection,  &quoted,
            &signature, &sessionsDataOut );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nQuote Failed ! ErrorCode: 0x%0x\n\n", rval);
        return -1;
    }

    printf( "\nquoted:\n " );
    PrintSizedBuffer( (TPM2B *)&quoted );
    //PrintTPM2B_ATTEST(&quoted);
    printf( "\nsignature:\n " );
    PrintBuffer( (UINT8 *)&signature, sizeof(signature) );
    //PrintTPMT_SIGNATURE(&signature);

    FILE *fp = fopen(outFilePath,"w+");
    if(NULL == fp)
    {
        printf("OutFile: %s Can Not Be Created !\n",outFilePath);
        return -2;
    }
    if(fwrite(&quoted, calcSizeofTPM2B_ATTEST(&quoted), 1 ,fp) != 1)
    {
        fclose(fp);
        printf("OutFile: %s Write quoted Data In Error!\n",outFilePath);
        return -3;
    }
    if(fwrite(&signature, calcSizeofTPMT_SIGNATURE(&signature), 1, fp) != 1)
    {
        fclose(fp);
        printf("OutFile: %s Write signature Data In Error!\n",outFilePath);
        return -4;
    }

    fclose(fp);
    return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "-h, --help               Display command tool usage info;\n"
            "-v, --version            Display command tool version info;\n"
            "-k, --akHandle <hexHandle>    Handle of existing AK\n"
            "-c, --akContext <filename>    filename for the existing AK's context\n"
            "-P, --akPassword <akPassword> AK handle's Password\n"
            "-l, --idList  <num1,...,numN> The list of selected PCR's id, 0~23\n"
            "-g, --algorithm <hexAlg>      The algorithm id\n"
            "-o, --outFile<filePath>       output file path, recording the two structures output by tpm2_quote function\n"
            "-p, --port    <port number>   The Port number, default is %d, optional\n"
            "-d, --debugLevel <0|1|2|3>    The level of debug message, default is 0, optional\n"
            "\t0 (high level test results)\n"
            "\t1 (test app send/receive byte streams)\n"
            "\t2 (resource manager send/receive byte streams)\n"
            "\t3 (resource manager tables)\n"
            "\n"
            "Example:\n"
            "display usage:   %s -h\n"
            "display version: %s -v\n"
            "quote the selected PCR values:\n"
            "\t %s -k 0x80000001 -P abc123 -g 0x4 -l 16,17,18 -o outFile001\n"
            "\t %s -c ak.context -P abc123 -g 0x4 -l 16,17,18 -o outFile001\n"
            "\t %s -k 0x80000001 -g 0x4 -l 16,17,18 -o outFile001 \n\n"
            "\t %s -c ak.context -g 0x4 -l 16,17,18 -o outFile001 \n\n"
            , name, DEFAULT_RESMGR_TPM_PORT, name, name, name, name, name, name);
}

int parseList(const char *arg, PCR_LIST *pcrList)
{
    char tmpStrCnt[128] = {0};
    char tmpStrParse[128] = {0};
    char tmpNum[10] = {0};
    int strLenth = strlen(arg);
    int listSize = 0;
    UINT32 selectedId = 0;
    if(strLenth == 0)
    {
        printf("The list can not be NULL!\n");
        return -1;
    }
    safeStrNCpy(tmpStrCnt, arg, sizeof(tmpStrCnt));
    safeStrNCpy(tmpStrParse, arg, sizeof(tmpStrParse));
    if(tmpStrCnt[0] == ',' || tmpStrCnt[strLenth-1] == ',')
    {
        printf("Wrong list: %s\n",arg);
        return -2;
    }
    for(int i=0; i<strLenth; i++)
    {
        if(tmpStrCnt[i] == ',')
            listSize++;
    }
    if(listSize == 0)
    {
        if( getPcrId(arg,&selectedId)!= 0 )
        {
            printf("Wrong list: %s\n",arg);
            return -3;
        }
        pcrList->size = listSize +1;
        pcrList->id[0]= selectedId;
        printf("size = 1; value=%d",pcrList->id[0]);
        return 0;
    }
    pcrList->size = listSize + 1;
    printf("pcrList->size = %d\n",pcrList->size);
    listSize = 0;
    for(int j=0,n=0; j<strLenth; j++,n++)
    {
        if(tmpStrParse[j] != ',')
        {
            tmpNum[n] = tmpStrParse[j];
        }
        else
        {
            n = -1;
            if(getPcrId(tmpNum, &selectedId)!= 0)
            {
                printf("Wrong list: %s\n",arg);
                return -4;
            }
            memset(tmpNum,0,10);
            pcrList->id[listSize] = selectedId;
            printf("pcrList->id[%d] = %d\n",listSize,pcrList->id[listSize]);
            listSize ++;
        }
    }
    if(getPcrId(tmpNum, &selectedId) != 0)
    {
        printf("Wrong list: %s\n",arg);
        return -5;
    }
    pcrList->id[listSize] = selectedId;
    printf("pcrList->id[%d] = %d\n",listSize,pcrList->id[listSize]);
    return 0;
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvk:c:P:l:g:o:p:d:";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
        {"version",0,NULL,'v'},
        {"akHandle",1,NULL,'k'},
        {"akContext",1,NULL,'c'},
        {"akPassword",1,NULL,'P'},  //add ak auth
        {"idList",1,NULL,'l'},
        {"algorithm",1,NULL,'g'},
        {"outFile",1,NULL,'o'},
        {"port",1,NULL,'p'},
        {"debugLevel",1,NULL,'d'},
        {0,0,0,0}
    };

    char *contextFilePath = NULL;
    TPM_HANDLE akHandle;
    TPMI_ALG_HASH algorithmId;
    PCR_LIST pcrList;

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        k_flag = 0,
        c_flag = 0,
        P_flag = 0,
        l_flag = 0,
        g_flag = 0,
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
        case 'k':
            if(getSizeUint32Hex(optarg,&akHandle) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -1;
                break;
            }
            k_flag = 1;
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

        case 'P':
            sessionData.hmac.t.size = sizeof(sessionData.hmac.t) - 2;
            if(str2ByteStructure(optarg,&sessionData.hmac.t.size,sessionData.hmac.t.buffer) != 0)
            {
                returnVal = -3;
                break;
            }
            P_flag = 1;
            break;
        case 'l':
            if(parseList(optarg, &pcrList) != 0)
            {
                returnVal = -4;
                break;
            }
            l_flag = 1;
            break;
        case 'g':
            if(getSizeUint16Hex(optarg,&algorithmId) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -5;
                break;
            }
            g_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -6;
                break;
            }
            o_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -7;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -8;
            }
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
        return returnVal;

    flagCnt = h_flag + v_flag + k_flag + c_flag + l_flag + g_flag + o_flag;
    if(flagCnt == 1)
    {
        if(h_flag == 1)
            showHelp(argv[0]);
        else if(v_flag == 1)
            showVersion(argv[0]);
        else
        {
            showArgMismatch(argv[0]);
            return -11;
        }
    }
    else if(flagCnt == 4 && ((k_flag || c_flag) && l_flag && g_flag && o_flag))
    {
        if(P_flag == 0)
            sessionData.hmac.t.size = 0;

        prepareTest(hostName, port, debugLevel);

        if(c_flag)
            returnVal = loadTpmContextFromFile(sysContext, &akHandle, contextFilePath);
        if(returnVal == TPM_RC_SUCCESS)
            returnVal = quote(akHandle, pcrList, algorithmId);

        finishTest();

        if(returnVal)
            return -12;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -13;
    }

    return 0;
}
