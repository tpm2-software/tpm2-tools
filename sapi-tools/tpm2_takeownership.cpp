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

char oldOwnerPasswd[sizeof(TPMU_HA)];
char oldEndorsePasswd[sizeof(TPMU_HA)];
char oldLockoutPasswd[sizeof(TPMU_HA)];
char newOwnerPasswd[sizeof(TPMU_HA)];
char newEndorsePasswd[sizeof(TPMU_HA)];
char newLockoutPasswd[sizeof(TPMU_HA)];

int clearHierarchyAuth()
{
    UINT32 rval;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    printf("\nStart to clear the Hierarchy auth....\n");
    rval = Tss2_Sys_ClearControl ( sysContext, TPM_RH_PLATFORM, &sessionsData, NO, 0 );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nClearControl Failed ! ErrorCode: 0x%0x\n\n", rval);
        return -1;
    }

    rval = Tss2_Sys_Clear ( sysContext, TPM_RH_PLATFORM, &sessionsData, 0 );
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nClear Failed ! ErrorCode: 0x%0x\n\n", rval);
        return -2;
    }

    return 0;
}

int changeHierarchyAuth()
{
    UINT32 rval;
    TPM2B_AUTH      newAuth;
    TPMS_AUTH_COMMAND sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];

    sessionDataArray[0] = &sessionData;
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsData.cmdAuthsCount = 1;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;

    // Change Owner Auth
    newAuth.t.size = strlen( newOwnerPasswd );
    memcpy( &newAuth.t.buffer[0], newOwnerPasswd, newAuth.t.size );

    sessionData.hmac.t.size = strlen( oldOwnerPasswd );
    memcpy( &sessionData.hmac.t.buffer[0], oldOwnerPasswd, sessionData.hmac.t.size );

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_OWNER, &sessionsData, &newAuth, 0 );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Change Hierarchy Owner Auth Error. TPM Error:0x%x......\n", rval);
        return -1;
    }
    printf("\n......Change Hierarchy Owner Auth Succ......\n");

    // Change Endorsement Auth
    newAuth.t.size = strlen( newEndorsePasswd );
    memcpy( &newAuth.t.buffer[0], newEndorsePasswd, newAuth.t.size );

    sessionData.hmac.t.size = strlen( oldEndorsePasswd );
    memcpy( &sessionData.hmac.t.buffer[0], oldEndorsePasswd, sessionData.hmac.t.size );

    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_ENDORSEMENT, &sessionsData, &newAuth, 0 );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Change Hierarchy Endorsement Auth Error. TPM Error:0x%x......\n", rval);
        return -2;
    }
    printf("\n......Change Hierarchy Endorsement Auth Succ......\n");

    // Change Lockout Auth
    newAuth.t.size = strlen( newLockoutPasswd );
    memcpy( &newAuth.t.buffer[0], newLockoutPasswd, newAuth.t.size );

    sessionData.hmac.t.size = strlen( oldLockoutPasswd );
    memcpy( &sessionData.hmac.t.buffer[0], oldLockoutPasswd, sessionData.hmac.t.size );
    rval = Tss2_Sys_HierarchyChangeAuth( sysContext, TPM_RH_LOCKOUT, &sessionsData, &newAuth, 0 );
    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......Change Hierarchy Lockout Auth Error. TPM Error:0x%x......\n", rval);
        return -3;
    }
    printf("\n......Change Hierarchy Lockout Auth Succ......\n");

    return 0;
}


void showHelp(const char *name)
{
    printf("\n%s: inserting authorization values for the owner, endorsement, and lockout.\n"
           "Usage: %s [-h/--help]\n"
           "   or: %s [-v/--version]\n"
           "   or: %s [-e/--endorsePasswd <password>] [-o/--ownerPasswd <password>] [-l/--lockPasswd <password>]\n"
           "                          [-E/--oldEndorsePasswd <password>] [-O/--oldOwnerPasswd <password>] [-L/--oldLockPasswd <password>]\n"
           "   or: %s [-e/--endorsePasswd <password>] [-o/--ownerPasswd <password>] [-l/--lockPasswd <password>]\n"
           "                          [-E/--oldEndorsePasswd <password>] [-O/--oldOwnerPasswd <password>] [-L/--oldLockPasswd <password>]\n"
           "                          [-p/--port <port>] [-d/--dbg <dbgLevel>]\n"
           "\nwhere:\n\n"
           "   -h/--help                        display this help and exit.\n"
           "   -v/--version                     display version information and exit.\n"
           "   -o/--ownerPasswd <password>      new Owner authorization value.\n"
           "   -e/--endorsePasswd <password>    new Endorsement authorization value.\n"
           "   -l/--lockPasswd <password>       new Lockout authorization value.\n"
           "   -O/--oldOwnerPasswd <password>   old Owner authorization (string,optional,default:NULL).\n"
           "   -E/--oldEndorsePasswd <password> old Endorsement authorization (string,optional,default:NULL).\n"
           "   -L/--oldLockPasswd <password>    old Lockout authorization (string,optional,default:NULL).\n"
           "   -p/--port <port>                 specifies the port number. default %d.\n"
           "   -d/--dbg <dbgLevel>              specifies level of debug messages:\n"
           "                                      0 (high level test results)\n"
           "                                      1 (test app send/receive byte streams)\n"
           "                                      2 (resource manager send/receive byte streams)\n"
           "                                      3 (resource manager tables)\n"
           "\nexample:\n"
           "   Set ownerAuth, endorsementAuth and lockoutAuth to emptyAuth: %s -c\n"
           "   Set ownerAuth, endorsementAuth and lockoutAuth to a newAuth: %s -o new -e new -l new -O old -E Old -L old\n"
           , name, name, name, name, name, DEFAULT_RESMGR_TPM_PORT, name, name);
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
    int opt;
    int clearAuth = 0;
    bool argsError = false;
    int returnVal = 0;

    struct option sOpts[] =
    {
        { "ownerPasswd"     , required_argument, NULL, 'o' },
        { "endorsePasswd"   , required_argument, NULL, 'e' },
        { "lockPasswd"      , required_argument, NULL, 'l' },
        { "oldOwnerPasswd"  , required_argument, NULL, 'O' },
        { "oldEndorsePasswd", required_argument, NULL, 'E' },
        { "oldLockPasswd"   , required_argument, NULL, 'L' },
        { "port"            , required_argument, NULL, 'p' },
        { "dbg"             , required_argument, NULL, 'd' },
        { "help"            , no_argument,       NULL, 'h' },
        { "version"         , no_argument,       NULL, 'v' },
        { "clear"           , no_argument,       NULL, 'c' },
        { NULL              , no_argument,       NULL,  0  },
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

    while ( ( opt = getopt_long( argc, argv, "o:e:l:O:E:L:p:d:hvc", sOpts, NULL ) ) != -1 )
    {
        switch ( opt ) {
        case 'h':
        case '?':
            showHelp(argv[0]);
            return 0;
        case 'v':
            showVersion(argv[0]);
            return 0;
        case 'c':
            clearAuth = 1;
            break;

        case 'o':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                argsError = true;
                break;
            }
            safeStrNCpy(newOwnerPasswd, optarg, sizeof(newOwnerPasswd));
            break;

        case 'e':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                argsError = true;
                break;
            }
            safeStrNCpy(newEndorsePasswd, optarg, sizeof(newEndorsePasswd));
            break;

        case 'l':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                argsError = true;
                break;
            }
            safeStrNCpy(newLockoutPasswd, optarg, sizeof(newLockoutPasswd));
            break;

        case 'O':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input current Owner authorization value(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -2;
            }
            safeStrNCpy(oldOwnerPasswd, optarg, sizeof(oldOwnerPasswd));
            break;

        case 'E':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input current Endorsement authorization value(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -3;
            }
            safeStrNCpy(oldEndorsePasswd, optarg, sizeof(oldEndorsePasswd));
            break;

        case 'L':
            if( optarg == NULL || (strlen(optarg) >= sizeof(TPMU_HA)) )
            {
                printf("\nPlease input current Lockout authorization value(optional,no more than %d characters).\n", (int)sizeof(TPMU_HA)-1);
                return -4;
            }
            safeStrNCpy(oldLockoutPasswd, optarg, sizeof(oldLockoutPasswd));
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                return -5;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                return -6;
            }
            break;

        default:
            showHelp(argv[0]);
            return -7;
        }
    }

    if( argsError == true )
    {
        showArgMismatch(argv[0]);
        return -8;
    }

    prepareTest(hostName, port, debugLevel) != 0;

    if( clearAuth )
        returnVal = clearHierarchyAuth();
    else
        returnVal = changeHierarchyAuth();

    finishTest();

    if(returnVal)
        return -9;

    return 0;
}

