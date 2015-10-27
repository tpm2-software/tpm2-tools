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
#include "sample.h"
#include "resourcemgr.h"
#include "tpmclient.h"
#include "tss2_sysapi_util.h"
#include "tpmsockets.h"
#include "syscontext.h"
#include "debug.h"
#include "common.h"

#define errorStringSize 200
char errorString[errorStringSize];

#define rmInterfaceConfigSize 250
char rmInterfaceConfig[rmInterfaceConfigSize];

TSS2_TCTI_DRIVER_INFO resMgrInterfaceInfo = { "resMgr", "", InitSocketsTcti, TeardownSocketsTcti };

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

FILE *outFp;
UINT8 simulator = 1;

TSS2_SYS_CONTEXT *sysContext;

#if 1
int TpmClientPrintf( UINT8 type, const char *format, ...)
{
    return 0;
}
#else
int TpmClientPrintf( UINT8 type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    OpenOutFile( &outFp );

    if( outFp )
    {
        if( type == RM_PREFIX )
        {
            PrintRMDebugPrefix();
        }

        va_start( args, format );
        rval = vfprintf( outFp, format, args );
        va_end (args);

        CloseOutFile( &outFp );
    }
    else
    {
        printf( "TpmClientPrintf failed\n" );
    }

    return rval;
}
#endif

int CompareTPM2B( TPM2B *buffer1, TPM2B *buffer2 )
{
    if( buffer1->size != buffer2->size )
        return -1;
    for( int i = 0; i < buffer1->size; i++ )
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

    sprintf_s( errorString, errorStringSize, "%s Error: 0x%x\n", levelString, rval );
}

char resMgrInterfaceName[] = "Resource Manager";

TSS2_RC InitTctiResMgrContext( char *rmInterfaceConfig, TSS2_TCTI_CONTEXT **tctiContext, char *name )
{
    size_t size;

    TSS2_RC rval;

    rval = resMgrInterfaceInfo.initialize(NULL, &size, rmInterfaceConfig, 0, 0, &resMgrInterfaceName[0], 0 );
    if( rval != TSS2_RC_SUCCESS )
        return rval;

    *tctiContext = (TSS2_TCTI_CONTEXT *)malloc(size);

    if( *tctiContext )
    {
        rval = resMgrInterfaceInfo.initialize(*tctiContext, &size, rmInterfaceConfig, 0, 0, resMgrInterfaceName, 0 );
    }
    else
    {
        rval = TSS2_TCTI_RC_BAD_CONTEXT;
    }
    return rval;
}

TSS2_RC TeardownTctiResMgrContext( char *interfaceConfig, TSS2_TCTI_CONTEXT *tctiContext, char *name )
{
    return resMgrInterfaceInfo.teardown( tctiContext, interfaceConfig, name );
}

void Cleanup()
{
    fflush( stdout );

    PlatformCommand( resMgrTctiContext, MS_SIM_POWER_OFF );

    TeardownTctiResMgrContext( rmInterfaceConfig, resMgrTctiContext, &resMgrInterfaceName[0] );

#ifdef _WIN32
    WSACleanup();
#endif
    exit(1);
}

void InitSysContextFailure()
{
    printf( "InitSysContext failed, exiting...\n" );
    Cleanup();
}

int prepareTest(const char *hostName, const int port, int debugLevel)
{
    TSS2_RC rval;

    sprintf_s( rmInterfaceConfig, rmInterfaceConfigSize, "%s %d ", hostName, port );

    rval = InitTctiResMgrContext( rmInterfaceConfig, &resMgrTctiContext, &resMgrInterfaceName[0] );
    if( rval != TSS2_RC_SUCCESS )
    {
        printf( "Resource Mgr, %s, failed initialization: 0x%x.  Exiting...\n", resMgrInterfaceInfo.shortName, rval );
        Cleanup();
    }
    else
    {
        (( TSS2_TCTI_CONTEXT_INTEL *)resMgrTctiContext )->status.debugMsgLevel = debugLevel;
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
    TeardownTctiResMgrContext( rmInterfaceConfig, resMgrTctiContext, &resMgrInterfaceName[0] );
    TeardownSysContext( &sysContext );
}


int getSizeUint16Hex(const char *arg, UINT16 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    safeStrNCpy(tmpArg, arg, sizeof(tmpArg));
    tmpSize = strtol(tmpArg,&errPtr,16);
    if(strlen(errPtr) != 0)
        return -2;
    if( tmpSize > 0xffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int getSizeUint16(const char *arg, UINT16 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    safeStrNCpy(tmpArg, arg, sizeof(tmpArg));
    tmpSize = strtol(tmpArg,&errPtr,10);
    if(strlen(errPtr) != 0)
        return -2;
    if( tmpSize > 0xffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int getSizeUint32Hex(const char *arg, UINT32 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    safeStrNCpy(tmpArg, arg, sizeof(tmpArg));
    tmpSize = strtoll(tmpArg,&errPtr,16);
    if(strlen(errPtr) != 0)
        return -2;
    if(tmpSize > 0xffffffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int getSizeUint32(const char *arg, UINT32 *num)
{
    char tmpArg[1024] = {0};
    char *errPtr;
    long tmpSize = 0;
    if (arg == NULL || num == NULL)
        return -1;
    safeStrNCpy(tmpArg, arg, sizeof(tmpArg));
    tmpSize = strtol(tmpArg,&errPtr,10);
    if(strlen(errPtr) != 0)
        return -2;
    if(tmpSize > 0xffffffff || tmpSize < 0)
        return -3;
    *num = tmpSize;
    return 0;
}

int str2ByteStructure(const char *inStr, UINT16 *byteLength, BYTE *byteBuffer)
{
    if(inStr == NULL || byteLength == NULL || byteBuffer == NULL)
        return -1;
    if(*byteLength <= strlen(inStr))
        return -2;

    *byteLength = strlen(inStr);
    memcpy(byteBuffer, inStr, *byteLength);
    byteBuffer[*byteLength] = '\0';
    return 0;
}

int hex2ByteStructure(const char *inStr, UINT16 *byteLength, BYTE *byteBuffer)
{
    int strLength;//if the inStr likes "1a2b...", no prefix "0x"
    int i = 0;
    if(inStr == NULL || byteLength == NULL || byteBuffer == NULL)
        return -1;
    strLength = strlen(inStr);
    if(strLength%2)
        return -2;
    for(i = 0; i < strLength; i++)
    {
        if(!isxdigit(inStr[i]))
            return -3;
    }

    if(*byteLength < strLength/2)
        return -4;

    *byteLength = strLength/2;

    for(i = 0; i < *byteLength; i++)
    {
        char tmpStr[3] = {0};
        tmpStr[0] = inStr[i*2];
        tmpStr[1] = inStr[i*2+1];
        byteBuffer[i] = strtol(tmpStr, NULL, 16);
    }
    return 0;
}

int loadDataFromFile(const char *fileName, UINT8 *buf, UINT16 *size)
{
    UINT16 count = 1, left;
    FILE *f;
    if ( size == NULL || buf == NULL || fileName == NULL )
        return -1;

    f = fopen(fileName, "rb+");
    if( f == NULL )
    {
        printf("File(%s) open error.\n", fileName);
        return -2;
    }

    left = *size;
    *size = 0;
    while( left > 0 && count > 0 )
    {
        count = fread(buf, 1, left, f);
        *size += count;
        left -= count;
        buf += count;
    }

    if( *size == 0 )
    {
        printf("File read error\n");
        fclose(f);
        return -3;
    }
    fclose(f);
    return 0;
}

int saveDataToFile(const char *fileName, UINT8 *buf, UINT16 size)
{
    FILE *f;
    UINT16 count = 1;
    if( fileName == NULL || buf == NULL || size == 0 )
        return -1;

    f = fopen(fileName, "wb+");
    if( f == NULL )
    {
        printf("File(%s) open error.\n", fileName);
        return -2;
    }

    while( size > 0 && count > 0 )
    {
        count = fwrite(buf, 1, size, f);
        size -= count;
        buf += count;
    }

    if( size > 0 )
    {
        printf("File write error\n");
        fclose(f);
        return -3;
    }

    fclose(f);
    return 0;
}

static TPMS_CONTEXT context;

int saveTpmContextToFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle, const char *fileName)
{
    TPM_RC rval;

    rval = Tss2_Sys_ContextSave( sysContext, handle, &context);
    if( rval == TPM_RC_SUCCESS &&
        saveDataToFile(fileName, (UINT8 *)&context, sizeof(TPMS_CONTEXT)) )
        rval == TPM_RC_FAILURE;

    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......ContextSave:Save handle 0x%x context failed. TPM Error:0x%x......\n", handle, rval);
        return -1;
    }

    return 0;
}

int loadTpmContextFromFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE *handle, const char *fileName)
{
    TPM_RC rval = TPM_RC_SUCCESS;
    UINT16 size = sizeof(TPMS_CONTEXT);

    if( loadDataFromFile(fileName, (UINT8 *)&context, &size) )
        rval = TPM_RC_FAILURE;
    if( rval == TPM_RC_SUCCESS )
        rval = Tss2_Sys_ContextLoad(sysContext, &context, handle);

    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......ContextLoad Error. TPM Error:0x%x......\n", rval);
        return -1;
    }

    return 0;
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

int checkOutFile(const char *path)
{
    FILE *fp = fopen(path,"rb");
    if(NULL != fp)
    {
        fclose(fp);
        printf("OutFile: %s Already Exist, Please Rename OR Delete It!\n",path);
        return -1;
    }
    return 0;
}

int getFileSize(const char *path, long *fileSize)
{
    FILE *fp = fopen(path,"rb");
    if(NULL == fp)
    {
        printf("File: %s  Not Found OR Access Error !\n",path);
        return -1;
    }
    fseek(fp, 0, SEEK_SET);
    fseek(fp, 0, SEEK_END);
    *fileSize = ftell(fp);
    fclose(fp);
    return 0;
}

int getPcrId(const char *arg, UINT32 *pcrId)
{
    UINT32 n = 0;

    if(arg == NULL || pcrId == NULL)
        return -1;

    if(getSizeUint32(arg, &n))
        return -2;

    if(n > 23)
        return -3;

    *pcrId = n;

    return 0;
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

