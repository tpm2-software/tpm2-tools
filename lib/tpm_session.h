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

#ifndef SRC_TPM2_SESSION_H_
#define SRC_TPM2_SESSION_H_

#include <tss2/tss2_sys.h>

typedef struct {
    // Inputs to StartAuthSession; these need to be saved
    // so that HMACs can be calculated.
    TPMI_DH_OBJECT tpmKey;
    TPMI_DH_ENTITY bind;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    TPM2B_MAX_BUFFER salt;
    TPM2_SE sessionType;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;

    // Outputs from StartAuthSession; these also need
    // to be saved for calculating HMACs and
    // other session related functions.
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonceTPM;

    // Internal state for the session
    TPM2B_DIGEST sessionKey;
    TPM2B_DIGEST authValueBind;     // authValue of bind object
    TPM2B_NONCE nonceNewer;
    TPM2B_NONCE nonceOlder;
    TPM2B_NONCE nonceTpmDecrypt;
    TPM2B_NONCE nonceTpmEncrypt;
    TPM2B_NAME name;                // Name of the object the session handle
                                    // points to.  Used for computing HMAC for
                                    // any HMAC sessions present.
                                    //
    void *hmacPtr;                  // Pointer to HMAC field in the marshalled
                                    // data stream for the session.
                                    // This allows the function to calculate
                                    // and fill in the HMAC after marshalling
                                    // of all the inputs.
                                    //
                                    // This is only used if the session is an
                                    // HMAC session.
                                    //
    UINT8 nvNameChanged;            // Used for some special case code
                                    // dealing with the NV written state.
} SESSION;

enum TSS2_APP_RC_CODE
{
    APP_RC_PASSED,
    APP_RC_GET_NAME_FAILED,
    APP_RC_CREATE_SESSION_KEY_FAILED,
    APP_RC_SESSION_SLOT_NOT_FOUND,
    APP_RC_BAD_ALGORITHM,
    APP_RC_SYS_CONTEXT_CREATE_FAILED,
    APP_RC_GET_SESSION_STRUCT_FAILED,
    APP_RC_GET_SESSION_ALG_ID_FAILED,
    APP_RC_INIT_SYS_CONTEXT_FAILED,
    APP_RC_TEARDOWN_SYS_CONTEXT_FAILED,
    APP_RC_BAD_LOCALITY
};

// Add this to application-specific error codes so they overlap
// with TSS ones which may be re-used for app level errors.
#define APP_RC_OFFSET 0x100

// These are app specific error codes, so they have
// APP_RC_OFFSET added.
#define TSS2_APP_RC_PASSED                      (APP_RC_PASSED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_GET_NAME_FAILED             (APP_RC_GET_NAME_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_CREATE_SESSION_KEY_FAILED   (APP_RC_CREATE_SESSION_KEY_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_SESSION_SLOT_NOT_FOUND      (APP_RC_SESSION_SLOT_NOT_FOUND + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_BAD_ALGORITHM               (APP_RC_BAD_ALGORITHM + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_SYS_CONTEXT_CREATE_FAILED   (APP_RC_SYS_CONTEXT_CREATE_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_GET_SESSION_STRUCT_FAILED   (APP_RC_GET_SESSION_STRUCT_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_GET_SESSION_ALG_ID_FAILED   (APP_RC_GET_SESSION_ALG_ID_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_INIT_SYS_CONTEXT_FAILED     (APP_RC_INIT_SYS_CONTEXT_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_TEARDOWN_SYS_CONTEXT_FAILED (APP_RC_TEARDOWN_SYS_CONTEXT_FAILED + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)
#define TSS2_APP_RC_BAD_LOCALITY                (APP_RC_BAD_LOCALITY + APP_RC_OFFSET + TSS2_APP_ERROR_LEVEL)

/* TODO DOCUMENT ME */
/**
 *
 * @param sapi_context
 * @param session
 * @param tpmKey
 * @param salt
 * @param bind
 * @param bindAuth
 * @param nonceCaller
 * @param encryptedSalt
 * @param sessionType
 * @param symmetric
 * @param algId
 * @return
 */
TSS2_RC tpm_session_start_auth_with_params(TSS2_SYS_CONTEXT *sapi_context, SESSION **session,
    TPMI_DH_OBJECT tpmKey, TPM2B_MAX_BUFFER *salt,
    TPMI_DH_ENTITY bind, TPM2B_AUTH *bindAuth, TPM2B_NONCE *nonceCaller,
    TPM2B_ENCRYPTED_SECRET *encryptedSalt,
    TPM2_SE sessionType, TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH algId );

/**
 *
 * @param session
 * @return
 */
void tpm_session_auth_end( SESSION *session);

#endif /* SRC_TPM2_SESSION_H_ */
