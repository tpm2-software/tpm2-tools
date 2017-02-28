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

#include <stdarg.h>
#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "pcr.h"
#include "string-bytes.h"

typedef struct {
    int size;
    UINT32 id[24];
} PCR_LIST;
TPMS_AUTH_COMMAND sessionData;
bool hexPasswd = false;
char outFilePath[PATH_MAX];
TPM2B_DATA qualifyingData = {{0,}};
TPML_PCR_SELECTION  pcrSelections;

void PrintBuffer( UINT8 *buffer, UINT32 size )
{
    UINT32 i;
    for( i = 0; i < size; i++ )
    {
        printf( "%2.2x", buffer[i] );
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

int quote(TSS2_SYS_CONTEXT *sapi_context, TPM_HANDLE akHandle, TPML_PCR_SELECTION *pcrSelection)
{
    UINT32 rval;
    TPMT_SIG_SCHEME inScheme;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_ATTEST quoted = { { sizeof(TPM2B_ATTEST)-2, } };
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
    if (sessionData.hmac.t.size > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (hex2ByteStructure((char *)sessionData.hmac.t.buffer,
                              &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for AK Passwd.\n");
            return -1;
        }
    }

    inScheme.scheme = TPM_ALG_NULL;

    memset( (void *)&signature, 0, sizeof(signature) );

    rval = Tss2_Sys_Quote(sapi_context, akHandle, &sessionsData,
            &qualifyingData, &inScheme, pcrSelection, &quoted,
            &signature, &sessionsDataOut );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nQuote Failed ! ErrorCode: 0x%0x\n\n", rval);
        return -1;
    }

    printf( "\nquoted:\n " );
    string_bytes_print_tpm2b( (TPM2B *)&quoted );
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

int execute_tool (int argc, char *argv[], char *envp[], common_opts_t *opts,
              TSS2_SYS_CONTEXT *sapi_context) {

    int opt = -1;
    const char *optstring = "hvk:c:P:l:g:L:o:Xq:";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
        {"version",0,NULL,'v'},
        {"akHandle",1,NULL,'k'},
        {"akContext",1,NULL,'c'},
        {"akPassword",1,NULL,'P'},  //add ak auth
        {"idList",1,NULL,'l'},
        {"algorithm",1,NULL,'g'},
        {"selList",1,NULL,'L'},
        {"outFile",1,NULL,'o'},
        {"passwdInHex",0,NULL,'X'},
        {"qualifyData",1,NULL,'q'},
        {0,0,0,0}
    };

    char *contextFilePath = NULL;
    TPM_HANDLE akHandle;

    int returnVal = 0;
    int flagCnt = 0;
    int k_flag = 0,
        c_flag = 0,
        P_flag = 0,
        l_flag = 0,
        g_flag = 0,
        L_flag = 0,
        o_flag = 0;

    if(argc == 1)
    {
        LOG_ERR("Invalid usage, try --help for help!");
        return 0;
    }
    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'k':
            if(!string_bytes_get_uint32(optarg,&akHandle))
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
                showArgError(optarg, argv[0]);
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
                showArgError(optarg, argv[0]);
                returnVal = -3;
                break;
            }
            P_flag = 1;
            break;
        case 'l':
            if(pcr_parse_list(optarg, strlen(optarg), &pcrSelections.pcrSelections[0]) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -4;
                break;
            }
            l_flag = 1;
            break;
        case 'g':
            if(!string_bytes_get_uint16(optarg,&pcrSelections.pcrSelections[0].hash))
            {
                showArgError(optarg, argv[0]);
                returnVal = -5;
                break;
            }
            pcrSelections.count = 1;
            g_flag = 1;
            break;
        case 'L':
            if(pcr_parse_selections(optarg, &pcrSelections) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -15;
                break;
            }
            L_flag = 1;
            break;
        case 'o':
            snprintf(outFilePath, sizeof(outFilePath), "%s", optarg);
            if(files_does_file_exist(outFilePath))
            {
                showArgError(optarg, argv[0]);
                returnVal = -6;
                break;
            }
            o_flag = 1;
            break;
        case 'X':
            hexPasswd = true;
            break;
        case 'q':
            qualifyingData.t.size = sizeof(qualifyingData) - 2;
            if(hex2ByteStructure(optarg,&qualifyingData.t.size,qualifyingData.t.buffer) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -14;
                break;
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

    flagCnt = k_flag + c_flag + l_flag + g_flag + L_flag + o_flag;
    if(((flagCnt == 3 && L_flag) || (flagCnt == 4 && (g_flag && l_flag)))
             && (k_flag || c_flag) && o_flag)
    {
        if(P_flag == 0)
            sessionData.hmac.t.size = 0;

        if(c_flag)
            returnVal = file_load_tpm_context_from_file(sapi_context, &akHandle, contextFilePath) != true;
        if(returnVal == TPM_RC_SUCCESS)
            returnVal = quote(sapi_context, akHandle, &pcrSelections);
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
