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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>
#include "sample.h"
#include <tcti/tcti_socket.h>
#include "syscontext.h"
#include "common.h"

#define errorStringSize 200
char errorString[errorStringSize];

TSS2_TCTI_CONTEXT *resMgrTctiContext = 0;
TSS2_ABI_VERSION abiVersion = { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL, TSS_SAPI_FIRST_VERSION };

UINT32 ( *ComputeSessionHmacPtr )(
        TSS2_SYS_CONTEXT *sysContext,
        TPMS_AUTH_COMMAND *cmdAuth, // Pointer to session input struct
        TPM_HANDLE entityHandle,             // Used to determine if we're accessing a different
        // resource than the bound resoure.
        TPM_RC responseCode,                 // Response code for the command, 0xffff for "none" is
        // used to indicate that no response code is present
        // (used for calculating command HMACs vs response HMACs).
        TPM_HANDLE handle1,                  // First handle == 0xff000000 indicates no handle
        TPM_HANDLE handle2,                  // Second handle == 0xff000000 indicates no handle
        TPMA_SESSION sessionAttributes,      // Current session attributes
        TPM2B_DIGEST *result,                // Where the result hash is saved.
        TPM_RC sessionCmdRval
        ) = TpmComputeSessionHmac;

TPM_RC ( *GetSessionAlgIdPtr )( TPMI_SH_AUTH_SESSION authHandle, TPMI_ALG_HASH *sessionAlgId ) = GetSessionAlgId;

TPM_RC ( *CalcPHash )( TSS2_SYS_CONTEXT *sysContext,TPM_HANDLE handle1, TPM_HANDLE handle2, TPMI_ALG_HASH authHash,
        TPM_RC responseCode, TPM2B_DIGEST *pHash ) = TpmCalcPHash;

UINT32 (*HmacFunctionPtr)( TPM_ALG_ID hashAlg, TPM2B *key,TPM2B **bufferList, TPM2B_DIGEST *result ) = TpmHmac;

UINT32 (*HashFunctionPtr)( TPMI_ALG_HASH hashAlg, UINT16 size, BYTE *data, TPM2B_DIGEST *result ) = TpmHash;

UINT32 (*HandleToNameFunctionPtr)( TPM_HANDLE handle, TPM2B_NAME *name ) = TpmHandleToName;

TSS2_SYS_CONTEXT *sysContext;

int CompareTPM2B( TPM2B *buffer1, TPM2B *buffer2 )
{
    int i;

    if( buffer1->size != buffer2->size )
        return -1;
    for( i = 0; i < buffer1->size; i++ )
    {
        if( buffer1->buffer[0] != buffer2->buffer[0] )
            return -2;
    }
    return 0;
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

#define LEVEL_STRING_SIZE 50

void ErrorHandler( UINT32 rval )
{
    UINT32 errorLevel = rval & TSS2_ERROR_LEVEL_MASK;
    char levelString[LEVEL_STRING_SIZE + 1];

    switch( errorLevel )
    {
        case TSS2_TPM_ERROR_LEVEL:
            strncpy( levelString, "TPM", LEVEL_STRING_SIZE );
            break;
        case TSS2_APP_ERROR_LEVEL:
            strncpy( levelString, "Application", LEVEL_STRING_SIZE );
            break;
        case TSS2_SYS_ERROR_LEVEL:
            strncpy( levelString, "System API", LEVEL_STRING_SIZE );
            break;
        case TSS2_SYS_PART2_ERROR_LEVEL:
            strncpy( levelString, "System API TPM encoded", LEVEL_STRING_SIZE );
            break;
        case TSS2_TCTI_ERROR_LEVEL:
            strncpy( levelString, "TCTI", LEVEL_STRING_SIZE );
            break;
        case TSS2_RESMGRTPM_ERROR_LEVEL:
            strncpy( levelString, "Resource Mgr TPM encoded", LEVEL_STRING_SIZE );
            break;
        case TSS2_RESMGR_ERROR_LEVEL:
            strncpy( levelString, "Resource Mgr", LEVEL_STRING_SIZE );
            break;
        case TSS2_DRIVER_ERROR_LEVEL:
            strncpy( levelString, "Driver", LEVEL_STRING_SIZE );
            break;
        default:
            strncpy( levelString, "Unknown Level", LEVEL_STRING_SIZE );
            break;
    }

    snprintf( errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval );
}

char resMgrInterfaceName[] = "Resource Manager";

TSS2_RC InitTctiResMgrContext( TCTI_SOCKET_CONF *rmInterfaceConfig, TSS2_TCTI_CONTEXT **tctiContext, char *name )
{
    size_t size;

    TSS2_RC rval;

    rval = InitSocketTcti(NULL, &size, rmInterfaceConfig, 0 );
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    *tctiContext = (TSS2_TCTI_CONTEXT *)malloc(size);

    if( *tctiContext )
    {
        rval = InitSocketTcti(*tctiContext, &size, rmInterfaceConfig, 0 );
    }
    else
    {
        rval = TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return rval;
}

void TeardownTctiResMgrContext( TSS2_TCTI_CONTEXT *tctiContext )
{
    tss2_tcti_finalize (tctiContext);
    free (tctiContext);
}

void Cleanup()
{
    fflush( stdout );

    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );

    TeardownTctiResMgrContext( resMgrTctiContext );

    exit(1);
}

void InitSysContextFailure()
{
    printf( "InitSysContext failed, exiting...\n" );
    Cleanup();
}

TCTI_SOCKET_CONF rmInterfaceConfig = {
    DEFAULT_HOSTNAME,
    DEFAULT_RESMGR_TPM_PORT
};

int prepareTest(const char *hostName, const int port, int debugLevel)
{
    TSS2_RC rval;

    rmInterfaceConfig.hostname = hostName;
    rmInterfaceConfig.port = port;

    rval = InitTctiResMgrContext( &rmInterfaceConfig, &resMgrTctiContext, &resMgrInterfaceName[0] );
    if( rval != TSS2_RC_SUCCESS )
    {
        printf( "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", "resMgr", rval );
        Cleanup();
    }

    sysContext = InitSysContext( 0, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
    {
        InitSysContextFailure();
    }

    // always send simulator platform command to RM,
    // will be igorened if RM not on simulator
    PlatformCommand( resMgrTctiContext ,MS_SIM_POWER_ON );
    PlatformCommand( resMgrTctiContext, MS_SIM_NV_ON );
    return 0;
}

void finishTest()
{
    TeardownTctiResMgrContext( resMgrTctiContext );
    TeardownSysContext( &sysContext );
}

//
// This function does a hash on an array of data strings.
//
static TPM_RC TpmHashSequenceEx( TPMI_ALG_HASH hashAlg, UINT32 numBuffers, TPM2B_MAX_BUFFER *bufferList, TPM2B_DIGEST *result )
{
    TPM_RC rval;
    TSS2_SYS_CONTEXT *sysContext;
    TPM2B_AUTH nullAuth;
    TPMI_DH_OBJECT sequenceHandle;
    int i;
    TPM2B emptyBuffer;
    TPMT_TK_HASHCHECK validation;

    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    nullAuth.t.size = 0;
    emptyBuffer.size = 0;

    // Set result size to 0, in case any errors occur
    result->b.size = 0;

    // Init input sessions struct
    cmdAuth.sessionHandle = TPM_RS_PW;
    cmdAuth.nonce.t.size = 0;
    *( (UINT8 *)((void *)&cmdAuth.sessionAttributes ) ) = 0;
    cmdAuth.hmac.t.size = 0;

    sysContext = InitSysContext( 3000, resMgrTctiContext, &abiVersion );
    if( sysContext == 0 )
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;

    rval = Tss2_Sys_HashSequenceStart( sysContext, 0, &nullAuth, hashAlg, &sequenceHandle, 0 );

    if( rval != TPM_RC_SUCCESS )
        return( rval );

    for( i = 0; i < numBuffers; i++ )
    {
        rval = Tss2_Sys_SequenceUpdate ( sysContext, sequenceHandle, &cmdAuthArray, &bufferList[i], 0 );

        if( rval != TPM_RC_SUCCESS )
            return( rval );
    }

    rval = Tss2_Sys_SequenceComplete ( sysContext, sequenceHandle, &cmdAuthArray, ( TPM2B_MAX_BUFFER *)&emptyBuffer,
            TPM_RH_PLATFORM, result, &validation, 0 );

    if( rval != TPM_RC_SUCCESS )
        return( rval );

    TeardownSysContext( &sysContext );

    return rval;
}

int computeDataHash(BYTE *buffer, UINT16 length, TPMI_ALG_HASH halg, TPM2B_DIGEST *result)
{
    UINT8 numBuffers = 0;
    UINT32 i;
    if(length <= MAX_DIGEST_BUFFER)
    {
        if( TpmHash(halg, length, buffer, result) == TPM_RC_SUCCESS)
            return 0;
        else
            return -1;
    }

    numBuffers = (length - 1) / MAX_DIGEST_BUFFER + 1;

    TPM2B_MAX_BUFFER *bufferList = (TPM2B_MAX_BUFFER *)calloc(numBuffers, sizeof(TPM2B_MAX_BUFFER));
    if(bufferList == NULL)
        return -2;

    for(i = 0; i < numBuffers - 1; i++)
    {
        bufferList[i].t.size = MAX_DIGEST_BUFFER;
        memcpy(bufferList[i].t.buffer, buffer + i * MAX_DIGEST_BUFFER, MAX_DIGEST_BUFFER);
    }
    bufferList[i].t.size = length - i * MAX_DIGEST_BUFFER;
    memcpy(bufferList[i].t.buffer, buffer + i * MAX_DIGEST_BUFFER, bufferList[i].t.size);

    TPM_RC rval = TpmHashSequenceEx(halg, numBuffers, bufferList, result);
    free(bufferList);
    return rval == TPM_RC_SUCCESS ? 0 : -3;
}

int getPort(const char *arg, int *port)
{
    UINT16 n = 0;

    if(arg == NULL || port == NULL)
        return -1;

    if(getSizeUint16(arg, &n))
        return -2;

    if(n < 1 || n > 65534)
        return -3;

    *port = n;

    return 0;
}


int getDebugLevel(const char *arg, int *dl)
{
    UINT16 n = 0;

    if(arg == NULL || dl == NULL)
        return -1;

    if(getSizeUint16(arg, &n))
        return -2;

    if(n > 3)
        return -3;

    *dl = n;

    return 0;
}
