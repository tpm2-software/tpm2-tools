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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm_kdfa.h"
#include "tpm2_alg_util.h"
#include "tpm2_session.h"
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
        const char *path;
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

TPMI_SH_AUTH_SESSION tpm2_session_get_handle(tpm2_session *session) {
    return session->output.session_handle;
}

TPM2_SE tpm2_session_get_type(tpm2_session *session) {
    return session->input->session_type;
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
        LOG_PERR(Tss2_Sys_StartAuthSession, rval);
    }

    return rval == TPM2_RC_SUCCESS;
}

void tpm2_session_free(tpm2_session **session) {

    tpm2_session *s = *session;
    if (s) {
        free(s->input);
        free(s);
        *session = NULL;
    }
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

    if (!sapi_context) {
        return session;
    }

    bool result = start_auth_session(sapi_context, session);
    if (!result) {
        tpm2_session_free(&session);
        return NULL;
    }

    return session;
}

#define SESSION_VERSION 1

/*
 * Checks that two types are equal in size.
 *
 * It works by leveraging the fact that C does not allow negative array sizes.
 * If the sizes are equal, the boolean equality operator will return 1, thus
 * a subtraction of 1 yields 0, which is a legal array size in C. In the false
 * case (ie sizes not equal), 0 - 1 is -1, which will cause the compiler to
 * complain.
 */
#define COMPILE_ASSERT_SIZE(a, b) \
    typedef char WRONG_SIZE_##a[(sizeof(a) == sizeof(b)) - 1]

// We check that the TSS library does not change sizes unbeknownst to us.
COMPILE_ASSERT_SIZE(TPM2_HANDLE, UINT32);
COMPILE_ASSERT_SIZE(TPMI_ALG_HASH, UINT16);
COMPILE_ASSERT_SIZE(TPM2_SE, UINT8);

tpm2_session *tpm2_session_restore(TSS2_SYS_CONTEXT *sys_ctx, const char *path) {

    tpm2_session *s = NULL;

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Could not open path \"%s\", due to error: \"%s\"",
                path, strerror(errno));
        return NULL;
    }

    uint32_t version;
    bool result = files_read_header(f, &version);

    TPM2_SE type;
    result = files_read_bytes(f, &type, sizeof(type));
    if (!result) {
        LOG_ERR("Could not read session type");
        goto out;
    }

    TPMI_ALG_HASH auth_hash;
    result = files_read_16(f, &auth_hash);
    if (!result) {
        LOG_ERR("Could not read session digest algorithm");
        goto out;
    }

    TPM2_HANDLE handle;
    result = files_read_32(f, &handle);
    if (!result) {
        LOG_ERR("Could not read session handle");
        goto out;
    }

    TPM2_HANDLE handle_from_context;
    result = files_load_tpm_context_from_file (sys_ctx, &handle_from_context, f);
    if (!result) {
        LOG_ERR("Could not load session context");
        goto out;
    }
    if (handle != handle_from_context) {
        LOG_WARN("Handle from tpm2_session disagrees with session context");
    }

    tpm2_session_data *d = tpm2_session_data_new(type);
    if (!d) {
        LOG_ERR("oom");
        goto out;
    }

    tpm2_session_set_authhash(d, auth_hash);

    s = tpm2_session_new(NULL, d);
    if (s) {
        s->output.session_handle = handle;
    }

    s->internal.path = path;

out:
    fclose(f);
    return s;
}

bool tpm2_session_save(TSS2_SYS_CONTEXT *sapi_context, tpm2_session *session,
        const char *path) {

    if (!session) {
        return true;
    }

    bool result = false;
    FILE *session_file = NULL;

    if (!path) {
        path = session->internal.path;
        if (!path) {
            LOG_ERR("Unknown path to save to");
            return false;
        }
    }

    session_file = fopen(path, "w+b");
    if (!session_file) {
        LOG_ERR("Could not open path \"%s\", due to error: \"%s\"",
                path, strerror(errno));
        goto out;
    }

    /*
     * Now write the session_type, handle and auth hash data to disk
     */
    result = files_write_header(session_file, SESSION_VERSION);
    if (!result) {
         LOG_ERR("Could not write context file header");
         goto out;
     }

     // UINT8 session type:
     TPM2_SE session_type = session->input->session_type;
     result = files_write_bytes(session_file, &session_type, sizeof(session_type));
     if (!result) {
         LOG_ERR("Could not write session type");
         goto out;
     }

     // UINT16 - auth hash digest
     result = files_write_16(session_file, tpm2_session_get_authhash(session));
     if (!result) {
         LOG_ERR("Could not write savedHandle");
         goto out;
     }

     // UINT32 - Handle
    TPM2_HANDLE handle = tpm2_session_get_handle(session);
     result = files_write_32(session_file, handle);
     if (!result) {
         LOG_ERR("Could not write handle");
         goto out;
     }

    /*
     * Save session context at end of tpm2_session. With tabrmd support it
     * can be reloaded under certain circumstances.
     */
    result = files_save_tpm_context_to_file(sapi_context, handle, session_file);
    if (!result) {
        LOG_ERR("Could not write session context");
    }

out:
    if (session_file) {
        fclose(session_file);
    }

    return result;
}

bool tpm2_session_restart(TSS2_SYS_CONTEXT *sapi_context, tpm2_session *s) {

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(s);

    TSS2_RC rval = Tss2_Sys_PolicyRestart(sapi_context, handle, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyRestart, rval);
    }

    return rval == TPM2_RC_SUCCESS;
}
