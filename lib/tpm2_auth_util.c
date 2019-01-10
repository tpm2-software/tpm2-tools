//**********************************************************************;
// Copyright (c) 2017-2018, Intel Corporation
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
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

#define HEX_PREFIX "hex:"
#define HEX_PREFIX_LEN sizeof(HEX_PREFIX) - 1

#define STR_PREFIX "str:"
#define STR_PREFIX_LEN sizeof(STR_PREFIX) - 1

#define SESSION_PREFIX "session:"
#define SESSION_PREFIX_LEN sizeof(SESSION_PREFIX) - 1

#define FILE_PREFIX "file:"
#define FILE_PREFIX_LEN sizeof(FILE_PREFIX) - 1

static bool handle_hex_password(const char *password, TPMS_AUTH_COMMAND *auth) {

    /* if it is hex, then skip the prefix */
    password += HEX_PREFIX_LEN;

    auth->hmac.size = BUFFER_SIZE(typeof(auth->hmac), buffer);
    int rc = tpm2_util_hex_to_byte_structure(password, &auth->hmac.size, auth->hmac.buffer);
    if (rc) {
        auth->hmac.size = 0;
        return false;
    }

    return true;
}

static bool handle_str_password(const char *password, TPMS_AUTH_COMMAND *auth) {

    /* str may or may not have the str: prefix */
    bool is_str_prefix = !strncmp(password, STR_PREFIX, STR_PREFIX_LEN);
    if (is_str_prefix) {
        password += STR_PREFIX_LEN;
    }

    /*
     * Per the man page:
     * "a return value of size or more means that the output was truncated."
     */
    size_t wrote = snprintf((char *)&auth->hmac.buffer, BUFFER_SIZE(typeof(auth->hmac), buffer), "%s", password);
    if (wrote >= BUFFER_SIZE(typeof(auth->hmac), buffer)) {
        auth->hmac.size = 0;
        return false;
    }

    auth->hmac.size = wrote;

    return true;
}

static bool handle_password(const char *password, TPMS_AUTH_COMMAND *auth) {

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (is_hex) {
        return handle_hex_password(password, auth);
    }

    /* must be string, handle it */
    return handle_str_password(password, auth);
}

static bool handle_session(ESYS_CONTEXT *ectx, const char *path, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session) {

    /* if it is session, then skip the prefix */
    path += SESSION_PREFIX_LEN;

    /* Make a local copy for manipulation */
    char tmp[PATH_MAX];
    size_t len = snprintf(tmp, sizeof(tmp), "%s", path);
    if (len >= sizeof(tmp)) {
        LOG_ERR("Path truncated");
        return false;
    }

    /*
     * Sessions can have an associated password/auth value denoted after
     * a + sign, ie session.ctx+foo, deal with it by
     * finding a +, splitting the string on it, and if
     * not a NULL byte after the +, use that as a password.
     */
    char *password = strchr(tmp, '+');
    if (password) {
        *password = '\0';
        password++;
        if (*password) {
            bool result = handle_password(password, auth);
            if (!result) {
                return false;
            }
        }
    }

    *session = tpm2_session_restore(ectx, tmp);
    if (!*session) {
        return false;
    }

    // TODO: is setting this necessary?
    ESYS_TR sessiontr = tpm2_session_get_handle(*session);
    bool ok = tpm2_util_esys_handle_to_sys_handle(ectx, sessiontr,
                &auth->sessionHandle);
    if (!ok) {
        LOG_WARN("Failed to set sessionHandle for auth");
    }

    bool is_trial = tpm2_session_is_trial(*session);
    if (is_trial) {
        LOG_ERR("A trial session cannot be used to authenticate, "
                "Please use an hmac or policy session");
        tpm2_session_free(session);
        return false;
    }

    return true;
}

static bool handle_file(const char *path, TPMS_AUTH_COMMAND *auth) {

    bool ret = false;
    char *tmp = NULL;

    path += FILE_PREFIX_LEN;

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Could not open file: \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    unsigned long file_size = 0;
    ret = files_get_file_size(f, &file_size, path);
    if (!ret) {
        goto out;
    }

    if (file_size + 1 <= file_size) {
        LOG_ERR("overflow: file_size too large");
        goto out;
    }

    tmp = calloc(file_size + 1, sizeof(char));
    if (!tmp) {
        LOG_ERR("oom");
        goto out;
    }

    ret = files_read_bytes(f, (UINT8 *)tmp, file_size);
    if (!ret) {
        goto out;
    }

    ret = handle_password(tmp, auth);

out:
    fclose(f);
    free(tmp);

    return ret;
}

bool tpm2_auth_util_from_optarg(ESYS_CONTEXT *ectx, const char *password,
    TPMS_AUTH_COMMAND *auth, tpm2_session **session) {

    bool is_session = !strncmp(password, SESSION_PREFIX, SESSION_PREFIX_LEN);
    if (is_session && !session) {
        LOG_ERR("Tool does not support sessions for this auth value");
        return false;
    }

    bool is_file = !strncmp(password, FILE_PREFIX, FILE_PREFIX_LEN);
    if (is_file) {
        return handle_file(password, auth);
    }

    return is_session ?
         handle_session(ectx, password, auth, session) :
         handle_password(password, auth);
}

ESYS_TR tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR for_auth,
            TPMS_AUTH_COMMAND *auth, tpm2_session *session) {

    // If we have a valid auth value, prefer it
    if (auth->hmac.size > 0) {
        TPM2_RC rval = Esys_TR_SetAuth(ectx, for_auth, &auth->hmac);
        if (rval != TPM2_RC_SUCCESS) {
            return ESYS_TR_NONE;
        }

        return ESYS_TR_PASSWORD;
    }

    // If we have a valid session, use that
    if (session) {
        return tpm2_session_get_handle(session);
    }

    // For an empty auth and no session use ESYS_TR_PASSWORD
    return ESYS_TR_PASSWORD;
}
