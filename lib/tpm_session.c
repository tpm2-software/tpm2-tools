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

#include <stdbool.h>
#include <stdlib.h>

#include <sapi/tpm20.h>

#include "string-bytes.h"
#include "tpm_kdfa.h"
#include "tpm_session.h"

/* for APP_RC_CREATE_SESSION_KEY_FAILED error code */

#define SESSIONS_ARRAY_COUNT MAX_NUM_SESSIONS+1

typedef struct {
    SESSION session;
    void *nextEntry;
} SESSION_LIST_ENTRY;

static SESSION_LIST_ENTRY *local_sessions_list = 0;
static INT16 local_session_entries_used = 0;

/*
 * GetDigestSize() was taken from the TSS code base
 * and moved here since it was not part of the public
 * exxported API at the time.
 */
typedef struct {
    TPM_ALG_ID  algId;
    UINT16      size;  // Size of digest
} HASH_SIZE_INFO;

HASH_SIZE_INFO   hashSizes[] = {
    {TPM_ALG_SHA1,          SHA1_DIGEST_SIZE},
    {TPM_ALG_SHA256,        SHA256_DIGEST_SIZE},
#ifdef TPM_ALG_SHA384
    {TPM_ALG_SHA384,        SHA384_DIGEST_SIZE},
#endif
#ifdef TPM_ALG_SHA512
    {TPM_ALG_SHA512,        SHA512_DIGEST_SIZE},
#endif
    {TPM_ALG_SM3_256,       SM3_256_DIGEST_SIZE},
    {TPM_ALG_NULL,0}
};

static UINT16 GetDigestSize( TPM_ALG_ID authHash )
{
    UINT32 i;
    for(i = 0; i < (sizeof(hashSizes)/sizeof(HASH_SIZE_INFO)); i++ )
    {
        if( hashSizes[i].algId == authHash )
            return hashSizes[i].size;
    }

    // If not found, return 0 size, and let TPM handle the error.
    return( 0 );
}

static TPM_RC AddSession( SESSION_LIST_ENTRY **sessionEntry )
{
    SESSION_LIST_ENTRY **newEntry;

    // find end of list.
    for( newEntry = &local_sessions_list; *newEntry != 0; *newEntry = ( (SESSION_LIST_ENTRY *)*newEntry)->nextEntry )
        ;

    // allocate space for session structure.
    *newEntry = malloc( sizeof( SESSION_LIST_ENTRY ) );
    if( *newEntry != 0 )
    {
        *sessionEntry = *newEntry;
        (*sessionEntry)->nextEntry = 0;
        local_session_entries_used++;
        return TPM_RC_SUCCESS;
    }
    else
    {
        return TSS2_APP_RC_SESSION_SLOT_NOT_FOUND;
    }
}


static void DeleteSession( SESSION *session )
{
    SESSION_LIST_ENTRY *predSession;
    void *newNextEntry;

    if( session == &local_sessions_list->session )
        local_sessions_list = 0;
    else
    {
        // Find predecessor.
        for( predSession = local_sessions_list;
                predSession != 0 && &( ( ( SESSION_LIST_ENTRY *)predSession->nextEntry )->session ) != session;
                predSession = predSession->nextEntry )
            ;

        if( predSession != 0 )
        {
            local_session_entries_used--;

            newNextEntry = &( (SESSION_LIST_ENTRY *)predSession->nextEntry)->nextEntry;

            free( predSession->nextEntry );

            predSession->nextEntry = newNextEntry;
        }
    }
}

//
// This is a wrapper function around the TPM2_StartAuthSession command.
// It performs the command, calculates the session key, and updates a
// SESSION structure.
//
static TPM_RC StartAuthSession(TSS2_SYS_CONTEXT *sapi_context, SESSION *session )
{
    TPM_RC rval;
    TPM2B_ENCRYPTED_SECRET key;
    char label[] = "ATH";
    UINT16 bytes;
    int i;

    key.t.size = 0;

    if( session->nonceOlder.t.size == 0 )
    {
        /* this is an internal routine to TSS and should be removed */
        session->nonceOlder.t.size = GetDigestSize( TPM_ALG_SHA1 );
        for( i = 0; i < session->nonceOlder.t.size; i++ )
            session->nonceOlder.t.buffer[i] = 0;
    }

    session->nonceNewer.t.size = session->nonceOlder.t.size;
    rval = Tss2_Sys_StartAuthSession( sapi_context, session->tpmKey, session->bind, 0,
            &( session->nonceOlder ), &( session->encryptedSalt ), session->sessionType,
            &( session->symmetric ), session->authHash, &( session->sessionHandle ),
            &( session->nonceNewer ), 0 );

    if( rval == TPM_RC_SUCCESS )
    {
        if( session->tpmKey == TPM_RH_NULL )
            session->salt.t.size = 0;
        if( session->bind == TPM_RH_NULL )
            session->authValueBind.t.size = 0;

        if( session->tpmKey == TPM_RH_NULL && session->bind == TPM_RH_NULL )
        {
            session->sessionKey.b.size = 0;
        }
        else
        {
            // Generate the key used as input to the KDF.
            // Generate the key used as input to the KDF.
            bool result = string_bytes_concat_buffer( (TPM2B_MAX_BUFFER *)&key, &( session->authValueBind.b ) );
            if (!result)
            {
               return TSS2_SYS_RC_BAD_VALUE;
            }

            result = string_bytes_concat_buffer( (TPM2B_MAX_BUFFER *)&key, &( session->salt.b ) );
            if (!result)
            {
                return TSS2_SYS_RC_BAD_VALUE;
            }

            bytes = GetDigestSize( session->authHash );

            if( key.t.size == 0 )
            {
                session->sessionKey.t.size = 0;
            }
            else
            {
                rval = tpm_kdfa(sapi_context, session->authHash, &(key.b), label, &( session->nonceNewer.b ),
                        &( session->nonceOlder.b ), bytes * 8, (TPM2B_MAX_BUFFER *)&( session->sessionKey ) );
            }

            if( rval != TPM_RC_SUCCESS )
            {
                return( TSS2_APP_RC_CREATE_SESSION_KEY_FAILED );
            }
        }

        session->nonceTpmDecrypt.b.size = 0;
        session->nonceTpmEncrypt.b.size = 0;
        session->nvNameChanged = 0;
    }

    return rval;
}

TPM_RC tpm_session_auth_end( SESSION *session )
{
    TPM_RC rval = TPM_RC_SUCCESS;

    DeleteSession( session );

    return rval;
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
TPM_RC tpm_session_start_auth_with_params(TSS2_SYS_CONTEXT *sapi_context, SESSION **session,
    TPMI_DH_OBJECT tpmKey, TPM2B_MAX_BUFFER *salt,
    TPMI_DH_ENTITY bind, TPM2B_AUTH *bindAuth, TPM2B_NONCE *nonceCaller,
    TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM_SE sessionType, TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH algId )
{
    TPM_RC rval;
    SESSION_LIST_ENTRY *sessionEntry;

    rval = AddSession( &sessionEntry );
    if( rval == TSS2_RC_SUCCESS )
    {
        *session = &sessionEntry->session;

        // Copy handles to session struct.
        (*session)->bind = bind;
        (*session)->tpmKey = tpmKey;

        // Copy nonceCaller to nonceOlder in session struct.
        // This will be used as nonceCaller when StartAuthSession
        // is called.
        memcpy( &(*session)->nonceOlder.b, &nonceCaller->b, sizeof(nonceCaller->b));

        // Copy encryptedSalt
        memcpy( &(*session)->encryptedSalt.b, &encryptedSalt->b, sizeof(encryptedSalt->b));

        // Copy sessionType.
        (*session)->sessionType = sessionType;

        // Init symmetric.
        (*session)->symmetric.algorithm = symmetric->algorithm;
        (*session)->symmetric.keyBits.sym = symmetric->keyBits.sym;
        (*session)->symmetric.mode.sym = symmetric->mode.sym;
        (*session)->authHash = algId;

        // Copy bind' authValue.
        if( bindAuth == 0 )
        {
            (*session)->authValueBind.b.size = 0;
        }
        else
        {
            memcpy( &( (*session)->authValueBind.b ), &( bindAuth->b ), sizeof(bindAuth->b));
        }

        // Calculate sessionKey
        if( (*session)->tpmKey == TPM_RH_NULL )
        {
            (*session)->salt.t.size = 0;
        }
        else
        {
            memcpy( &(*session)->salt.b, &salt->b, sizeof(salt->b));
        }

        if( (*session)->bind == TPM_RH_NULL )
            (*session)->authValueBind.t.size = 0;


        rval = StartAuthSession(sapi_context, *session );
    }
    else
    {
        DeleteSession( *session );
    }
    return( rval );
}
