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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct {
    int size;
    UINT32 id[24];
} PCR_LIST;

static TPMS_AUTH_COMMAND sessionData;
static char *outFilePath;
static TPM2B_DATA qualifyingData = TPM2B_EMPTY_INIT;
static TPML_PCR_SELECTION  pcrSelections;
static bool is_auth_session;
static TPMI_SH_AUTH_SESSION auth_session_handle;
static int k_flag, c_flag, l_flag, g_flag, L_flag, o_flag;
static char *contextFilePath;
static TPM_HANDLE akHandle;

static void PrintBuffer( UINT8 *buffer, UINT32 size )
{
    UINT32 i;
    for( i = 0; i < size; i++ )
    {
        tpm2_tool_output("%2.2x", buffer[i]);
    }
    tpm2_tool_output("\n");
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

static UINT16 calcSizeofTPM2B_ATTEST( TPM2B_ATTEST *attest )
{
    return 2 + attest->b.size;
}

static UINT16  calcSizeofTPMT_SIGNATURE( TPMT_SIGNATURE *sig )
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

static int quote(TSS2_SYS_CONTEXT *sapi_context, TPM_HANDLE akHandle, TPML_PCR_SELECTION *pcrSelection)
{
    UINT32 rval;
    TPMT_SIG_SCHEME inScheme;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPM2B_ATTEST quoted = TPM2B_TYPE_INIT(TPM2B_ATTEST, attestationData);
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
    if (is_auth_session) {
        sessionData.sessionHandle = auth_session_handle;
    }

    sessionData.nonce.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

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
    tpm2_util_print_tpm2b( (TPM2B *)&quoted );
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
    if(fwrite(&signature, calcSizeofTPMT_SIGNATURE(&signature), required_argument, fp) != 1)
    {
        fclose(fp);
        printf("OutFile: %s Write signature Data In Error!\n",outFilePath);
        return -4;
    }

    fclose(fp);
    return 0;
}

static bool on_option(char key, char *value) {

    switch(key)
    {
    case 'k':
        if(!tpm2_util_string_to_uint32(value, &akHandle))
        {
            LOG_ERR("Invalid AK handle, got\"%s\"", value);
            return false;
        }
        k_flag = 1;
        break;
    case 'c':
        contextFilePath = optarg;
        c_flag = 1;
        break;

    case 'P': {
        bool res = tpm2_password_util_from_optarg(value, &sessionData.hmac);
        if (!res) {
            LOG_ERR("Invalid AK password, got\"%s\"", value);
            return false;
        }
    } break;
    case 'l':
        if(!pcr_parse_list(value, strlen(value), &pcrSelections.pcrSelections[0]))
        {
            LOG_ERR("Could not parse pcr list, got: \"%s\"", value);
            return false;
        }
        l_flag = 1;
        break;
    case 'g':
        pcrSelections.pcrSelections[0].hash = tpm2_alg_util_from_optarg(optarg);
        if (pcrSelections.pcrSelections[0].hash == TPM_ALG_ERROR)
        {
            LOG_ERR("Could not convert pcr hash selection, got: \"%s\"", value);
            return false;
        }
        pcrSelections.count = 1;
        g_flag = 1;
        break;
    case 'L':
        if(!pcr_parse_selections(value, &pcrSelections))
        {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        L_flag = 1;
        break;
    case 'o':
        outFilePath = optarg;
        o_flag = 1;
        break;
    case 'q':
        qualifyingData.t.size = sizeof(qualifyingData) - 2;
        if(tpm2_util_hex_to_byte_structure(value,&qualifyingData.t.size,qualifyingData.t.buffer) != 0)
        {
            LOG_ERR("Could not convert \"%s\" from a hex string to byte array!", value);
            return false;
        }
        break;
    case 'S':
         if (!tpm2_util_string_to_uint32(value, &auth_session_handle)) {
             LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                     optarg);
             return false;
         }
         is_auth_session = true;
         break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "akHandle",             required_argument, NULL, 'k' },
        { "akContext",            required_argument, NULL, 'c' },
        { "akPassword",           required_argument, NULL, 'P' },
        { "idList",               required_argument, NULL, 'l' },
        { "algorithm",            required_argument, NULL, 'g' },
        { "selList",              required_argument, NULL, 'L' },
        { "outFile",              required_argument, NULL, 'o' },
        { "qualifyData",          required_argument, NULL, 'q' },
        { "input-session-handle", required_argument, NULL, 'S' },
        { NULL }
    };

    *opts = tpm2_options_new("k:c:P:l:g:L:o:S:q:", ARRAY_LEN(topts), topts,
            on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    /* TODO this whole file needs to be re-done, especially the option validation */
    if (!o_flag) {
        LOG_ERR("Expected -o option to be specified");
        return 1;
    }

    if (!l_flag && !L_flag) {
        LOG_ERR("Expected either -l or -L to be specified");
        return 1;
    }

    if(c_flag) {
        bool result = files_load_tpm_context_from_file(sapi_context, &akHandle, contextFilePath);
        if (!result) {
            return 1;
        }
    }

    return quote(sapi_context, akHandle, &pcrSelections);
}
