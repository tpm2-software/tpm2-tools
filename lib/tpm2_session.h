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

#include <stdbool.h>

#include <tss2/tss2_sys.h>

typedef struct tpm2_session_data tpm2_session_data;
typedef struct tpm2_session tpm2_session;

/**
 * Creates a new session data object, based around the inputs to
 * TPM2_StartAuthSession as listed in Section 11.1:
 *   https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
 *
 * The defaults are set to:
 *   tpmKey = TPM2_RH_NULL
 *   bind = TPM2_RH_NULL
 *   nonceCaller = a SHA1 hash of all 0s.
 *   encryptedSalt = Empty Buffer
 *   symmetric = TPM2_ALG_NULL
 *   authHash = TPM2_ALG_SHA256
^ *
 * @param type
 *  The type of policy session, one of:
 *    - TPM2_SE_HMAC   - For an HMAC session.
 *    - TPM2_SE_POLICY - For a policy session.
 *    - TPM2_SE_TRIAL  - For a trial session, useful for building policies.
 * @return
 *  A tpm2_session_data object on success, NULL on failure.
 */
tpm2_session_data *tpm2_session_data_new(TPM2_SE type);

/**
 * Sets the tpmKey parameter.
 * @param data
 *  The session data object to modify.
 * @param key
 *  The tpmKey parameter value itself.
 */
void tpm2_session_set_key(tpm2_session_data *data, TPMI_DH_OBJECT key);

/**
 * Sets the nonceCaller parameter.
 * @param data
 *  The session data object to modify.
 * @param nonce
 *  The nonce parameter value itself.
 */
void tpm2_session_set_nonce_caller(tpm2_session_data *data, TPM2B_NONCE *nonce);

/**
 * Sets the bind parameter.
 * @param data
 *  The session data object to modify.
 * @param bind
 *  The bind parameter value itself.
 */
void tpm2_session_set_bind(tpm2_session_data *data, TPMI_DH_ENTITY bind);

/**
 * Sets the encryptedSalt parameter.
 * @param data
 *  The session data object to modify.
 * @param encsalt
 *  The encryptedSalt parameter value itself.
 */
void tpm2_session_set_encryptedsalt(tpm2_session_data *data,
        TPM2B_ENCRYPTED_SECRET *encsalt);

/**
 * Sets the symmetric parameter.
 * @param data
 *  The session data object to modify.
 * @param symmetric
 *  The symmetric parameter value itself.
 */
void tpm2_session_set_symmetric(tpm2_session_data *data,
        TPMT_SYM_DEF *symmetric);

/**
 * Sets the authHash parameter.
 * @param data
 *  The session data object to modify.
 * @param auth_hash
 *  The authHash parameter value itself.
 */
void tpm2_session_set_authhash(tpm2_session_data *data, TPMI_ALG_HASH auth_hash);

/**
 * Retrieves the authHash parameter used to start the authorization session.
 * @param session
 *  The tpm2_session started with tpm2_session_new().
 * @return
 *  The authHash value.
 */
TPMI_ALG_HASH tpm2_session_get_authhash(tpm2_session *session);

/**
 * Retrieves the session handle from starting the authorization session
 * with tpm2_session_new().
 * @param session
 *  The session started with tpm2_session_new().
 * @return
 *  The session handle.
 */
TPMI_SH_AUTH_SESSION tpm2_session_get_handle(tpm2_session *session);

/**
 * Retrieves the type of session, ie trial or policy session.
 * @param session
 * @return
 *  The type of the session, either TPM2_SE_HMAC, TPM2_SE_POLICY or
 *  TPM2_SE_TRIAL.
 */
TPM2_SE tpm2_session_get_type(tpm2_session *session);

/**
 * True if a session is of type TPM2_SE_TRIAL
 * @param session
 *  The session to check the type of.
 * @return
 *  True if a session is of type TPM2_SE_TRIAL, false otherwise.
 */
static inline bool tpm2_session_is_trial(tpm2_session *session) {
    return tpm2_session_get_type(session) == TPM2_SE_TRIAL;
}

/**
 * Starts a session with the tpm via Tss2_Sys_StartAuthSession().
 * @param sapi_context
 *  The system api context.
 * @param data
 *  A session data object created with tpm2_session_data_new() and potentially
 *  modified with the tpm2_session_data_set_*() routines.
 *  This pointer is owned by the tpm2_session object and the caller can
 *  forget about it at this point.
 * @return
 *  A tpm2_session object and a started tpm session or NULL on failure.
 */
tpm2_session *tpm2_session_new(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session_data *data);

/**
 * Saves session data to disk allowing tpm2_session_from_file() to
 * restore the session.
 *
 * @Note
 * This is accomplished by calling:
 *   - Tss2_Sys_ContextSave - marks to some RMs like tpm2-abrmd not to flush this session
 *                            handle on client disconnection.
 *   - Tss2_Sys_ContextLoad - restores the session so it can be used.
 *   - Saving a custom file format at path - records the handle and algorithm.
 * @param session
 *  The session context to save
 * @param sapi_context
 *  The system api context
 * @param path
 *  The path to save the session context too.
 * @return
 *  True on success, false otherwise.
 */
bool tpm2_session_save(TSS2_SYS_CONTEXT *sapi_context, tpm2_session *session,
        const char *path);

/**
 * Restores a session saved with tpm2_session_save().
 * @param path
 *  The path to restore from.
 * @return
 *  NULL on failure or a session pointer on success.
 */
tpm2_session *tpm2_session_restore(TSS2_SYS_CONTEXT *sys_ctx, const char *path);

/**
 * restarts the session to it's initial state via a call to
 * Tss2_Sys_PolicyRestart().
 * @param sapi_context
 *  The system api context
 * @param s
 *  The session
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_session_restart(TSS2_SYS_CONTEXT *sapi_context, tpm2_session *s);

/**
 * Frees a tpm2_sessio but DOES NOT FLUSH the handle. Frees the associated
 * tpm2_session_data object as well.
 * @param session
 *  The tpm2_session to free and set to NULL.
 */
void tpm2_session_free(tpm2_session **session);

#endif /* SRC_TPM2_SESSION_H_ */
