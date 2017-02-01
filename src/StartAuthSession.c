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

#include <sapi/tpm20.h>
#include "sample.h"
#include <stdlib.h>

#include "tpm_session.h"

#define SESSIONS_ARRAY_COUNT MAX_NUM_SESSIONS+1

typedef struct {
    SESSION session;
    void *nextEntry;
} SESSION_LIST_ENTRY;

SESSION_LIST_ENTRY *sessionsList = 0;
INT16 sessionEntriesUsed = 0;


TPM_RC AddSession( SESSION_LIST_ENTRY **sessionEntry )
{
    SESSION_LIST_ENTRY **newEntry;
    
    // find end of list.
    for( newEntry = &sessionsList; *newEntry != 0; *newEntry = ( (SESSION_LIST_ENTRY *)*newEntry)->nextEntry )
        ;

    // allocate space for session structure.
    *newEntry = malloc( sizeof( SESSION_LIST_ENTRY ) );
    if( *newEntry != 0 )
    {
        *sessionEntry = *newEntry;
        (*sessionEntry)->nextEntry = 0;
        sessionEntriesUsed++;
        return TPM_RC_SUCCESS;
    }
    else
    {
        return TSS2_APP_RC_SESSION_SLOT_NOT_FOUND;
    }
} 


void DeleteSession( SESSION *session )
{
    SESSION_LIST_ENTRY *predSession;
    void *newNextEntry;

    if( session == &sessionsList->session )
        sessionsList = 0;
    else
    {
        // Find predecessor.
        for( predSession = sessionsList;
                predSession != 0 && &( ( ( SESSION_LIST_ENTRY *)predSession->nextEntry )->session ) != session;
                predSession = predSession->nextEntry )
            ;

        if( predSession != 0 )
        {
            sessionEntriesUsed--;

            newNextEntry = &( (SESSION_LIST_ENTRY *)predSession->nextEntry)->nextEntry;

            free( predSession->nextEntry );

            predSession->nextEntry = newNextEntry;
        }
    }
}


TPM_RC GetSessionStruct( TPMI_SH_AUTH_SESSION sessionHandle, SESSION **session )
{
    TPM_RC rval = TSS2_APP_RC_GET_SESSION_STRUCT_FAILED;
    SESSION_LIST_ENTRY *sessionEntry;

    if( session != 0 )
    {
        //
        // Get pointer to session structure using the sessionHandle
        //
        for( sessionEntry = sessionsList;
                sessionEntry != 0 && sessionEntry->session.sessionHandle != sessionHandle;
                sessionEntry = sessionEntry->nextEntry )
            ;

        if( sessionEntry != 0 )
        {
            *session = &sessionEntry->session;
            rval = TSS2_RC_SUCCESS;
        }
    }
    return rval;
}

TPM_RC GetSessionAlgId( TPMI_SH_AUTH_SESSION sessionHandle, TPMI_ALG_HASH *sessionAlgId )
{
    TPM_RC rval = TSS2_APP_RC_GET_SESSION_ALG_ID_FAILED;
    SESSION *session;

    rval = GetSessionStruct( sessionHandle, &session );

    if( rval == TSS2_RC_SUCCESS )
    {
        *sessionAlgId = session->authHash;
        rval = TSS2_RC_SUCCESS;
    }

    return rval;
}

void RollNonces( SESSION *session, TPM2B_NONCE *newNonce  )
{
    session->nonceOlder = session->nonceNewer;
    session->nonceNewer = *newNonce;
}


//
// This version of StartAuthSession initializes the fields
// of the session structure using the passed in
// parameters, then calls StartAuthSession
// with just a pointer to the session structure.
// This allows all params to be set in one line of code when
// the function is called; cleaner this way, for
// some uses.
//
TPM_RC StartAuthSessionWithParams( SESSION **session,
    TPMI_DH_OBJECT tpmKey, TPM2B_MAX_BUFFER *salt, 
    TPMI_DH_ENTITY bind, TPM2B_AUTH *bindAuth, TPM2B_NONCE *nonceCaller,
    TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM_SE sessionType, TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH algId )
{

    TSS2_SYS_CONTEXT *tmpSysContext = InitSysContext( 1000, resMgrTctiContext, &abiVersion );
    if (!tmpSysContext)
        return TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED;
    TPM_RC rval = tpm_session_start_auth_with_params(tmpSysContext, session, tpmKey,
            salt, bind, bindAuth, nonceCaller, encryptedSalt, sessionType, symmetric, algId);
    TeardownSysContext( &tmpSysContext );
    return rval;
}

TPM_RC EndAuthSession( SESSION *session )
{
    return tpm_session_auth_end(session);
}   

