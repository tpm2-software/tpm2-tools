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
#include <stdbool.h>
#include <string.h>

#include <tss2/tss2_sys.h>

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

static bool handle_hex(const char *password, TPMS_AUTH_COMMAND *auth) {

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

static bool handle_session(TSS2_SYS_CONTEXT *sys_ctx, const char *path, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session) {

    /* if it is session, then skip the prefix */
    path += SESSION_PREFIX_LEN;

    *session = tpm2_session_restore(sys_ctx, path);
    if (!*session) {
        return false;
    }

    auth->sessionHandle = tpm2_session_get_handle(*session);

    bool is_trial = tpm2_session_is_trial(*session);
    if (is_trial) {
        LOG_ERR("A trial session cannot be used to authenticate, "
                "Please use an hmac or policy session");
        tpm2_session_free(session);
        return false;
    }

    return true;
}

static bool handle_str(const char *password, TPMS_AUTH_COMMAND *auth) {

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

bool tpm2_auth_util_from_optarg(TSS2_SYS_CONTEXT *sys_ctx, const char *password, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session) {

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (is_hex) {
        return handle_hex(password, auth);
    }

    bool is_session = !strncmp(password, SESSION_PREFIX, SESSION_PREFIX_LEN);
    if (is_session) {
        if (!session) {
            LOG_ERR("Tool does not support sessions for this auth value");
            return false;
        }
        return handle_session(sys_ctx, password, auth, session);
    }

    /* must be string, handle it */
    return handle_str(password, auth);
}
