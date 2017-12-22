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

#include "tpm2_session.h"

#include <stdbool.h>
#include <stdlib.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm_kdfa.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

struct tpm2_session_data {
    TPMI_DH_OBJECT key;
    TPMI_DH_ENTITY bind;
    TPM2B_ENCRYPTED_SECRET encrypted_salt;
    TPM2_SE session_type;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;
    TPM2B_NONCE nonce_caller;
};

struct tpm2_session {

    tpm2_session_data* input;

    struct {
        TPMI_SH_AUTH_SESSION session_handle;
        TPM2B_NONCE nonceTPM;
    } output;

    struct {
        TPM2B_NONCE nonceNewer;
    } internal;
};

tpm2_session_data *tpm2_session_data_new(TPM2_SE type) {
    tpm2_session_data * d = calloc(1, sizeof(tpm2_session_data));
    if (d) {
        d->symmetric.algorithm = TPM2_ALG_NULL;
        d->key = TPM2_RH_NULL;
        d->bind = TPM2_RH_NULL;
        d->session_type = type;
        d->authHash = TPM2_ALG_SHA256;
        d->nonce_caller.size = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA1);
    }
    return d;
}

void tpm2_session_set_key(tpm2_session_data *data, TPMI_DH_OBJECT key) {
    data->key = key;
}

void tpm2_session_set_nonce_caller(tpm2_session_data *data, TPM2B_NONCE *nonce) {
    data->nonce_caller = *nonce;
}

void tpm2_session_set_bind(tpm2_session_data *data, TPMI_DH_ENTITY bind) {
    data->bind = bind;
}

void tpm2_session_set_encryptedsalt(tpm2_session_data *data,
        TPM2B_ENCRYPTED_SECRET *encsalt) {
    data->encrypted_salt = *encsalt;
}

void tpm2_session_set_type(tpm2_session_data *data, TPM2_SE type) {
    data->session_type = type;
}

void tpm2_session_set_symmetric(tpm2_session_data *data,
        TPMT_SYM_DEF *symmetric) {
    data->symmetric = *symmetric;
}

void tpm2_session_set_authhash(tpm2_session_data *data, TPMI_ALG_HASH auth_hash) {
    data->authHash = auth_hash;
}

TPMI_ALG_HASH tpm2_session_get_authhash(tpm2_session *session) {
    return session->input->authHash;
}

TPMI_SH_AUTH_SESSION tpm2_session_get_session_handle(tpm2_session *session) {
    return session->output.session_handle;
}

//
// This is a wrapper function around the TPM2_StartAuthSession command.
// It performs the command, calculates the session key, and updates a
// SESSION structure.
//
static bool start_auth_session(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session *session) {

    tpm2_session_data *d = session->input;

    TSS2_RC rval = Tss2_Sys_StartAuthSession(sapi_context, d->key, d->bind,
            NULL, &session->input->nonce_caller, &d->encrypted_salt,
            d->session_type, &d->symmetric, d->authHash,
            &session->output.session_handle, &session->internal.nonceNewer,
            NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("StartAuthSession: 0x%x", rval);
    }

    return rval == TPM2_RC_SUCCESS;
}

void tpm2_session_free(tpm2_session **session) {

    tpm2_session *s = *session;
    free(s->input);
    free(s);
    *session = NULL;
}

tpm2_session *tpm2_session_new(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session_data *data) {

    tpm2_session *session = calloc(1, sizeof(tpm2_session));
    if (!session) {
        free(data);
        LOG_ERR("oom");
        return NULL;
    }

    session->input = data;

    session->internal.nonceNewer.size = session->input->nonce_caller.size;

    bool result = start_auth_session(sapi_context, session);
    if (!result) {
        tpm2_session_free(&session);
        return NULL;
    }

    return session;
}
