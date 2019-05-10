/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_policy.h"
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

#define PCR_PREFIX "pcr:"
#define PCR_PREFIX_LEN sizeof(PCR_PREFIX) - 1


static bool handle_hex_password(const char *password, TPM2B_AUTH *auth) {

    /* if it is hex, then skip the prefix */
    password += HEX_PREFIX_LEN;

    auth->size = BUFFER_SIZE(typeof(*auth), buffer);
    int rc = tpm2_util_hex_to_byte_structure(password, &auth->size, auth->buffer);
    if (rc) {
        auth->size = 0;
        return false;
    }

    return true;
}

static bool handle_str_password(const char *password, TPM2B_AUTH *auth) {

    /* str may or may not have the str: prefix */
    bool is_str_prefix = !strncmp(password, STR_PREFIX, STR_PREFIX_LEN);
    if (is_str_prefix) {
        password += STR_PREFIX_LEN;
    }

    /*
     * Per the man page:
     * "a return value of size or more means that the output was truncated."
     */
    size_t wrote = snprintf((char *)&auth->buffer, BUFFER_SIZE(typeof(*auth), buffer), "%s", password);
    if (wrote >= BUFFER_SIZE(typeof(*auth), buffer)) {
        auth->size = 0;
        return false;
    }

    auth->size = wrote;

    return true;
}

static bool handle_password(const char *password, TPM2B_AUTH *auth) {

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (is_hex) {
        return handle_hex_password(password, auth);
    }

    /* must be string, handle it */
    return handle_str_password(password, auth);
}

static tpm2_session *start_hmac_session(ESYS_CONTEXT *ectx, TPM2B_AUTH *auth) {

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_HMAC);
    if (!d) {
        LOG_ERR("oom");
        return NULL;
    }

    tpm2_session *s = tpm2_session_open(ectx, d);
    if (!s) {
        LOG_ERR("oom");
        return NULL;
    }

    tpm2_session_set_auth_value(s, auth);

    return s;
}

static bool handle_password_session(ESYS_CONTEXT *ectx, const char *password, tpm2_session **session) {

    TPM2B_AUTH auth = { 0 };
    bool result = handle_password(password, &auth);
    if (!result) {
        return result;
    }

    *session = start_hmac_session(ectx, &auth);

    return *session != NULL;
}

static bool handle_session(ESYS_CONTEXT *ectx, const char *path,
        tpm2_session **session) {

    TPM2B_AUTH auth = { 0 };

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
            bool result = handle_password(password, &auth);
            if (!result) {
                return false;
            }
        }
    }

    *session = tpm2_session_restore(ectx, tmp, false);
    if (!*session) {
        return false;
    }

    tpm2_session_set_auth_value(*session, &auth);

    bool is_trial = tpm2_session_is_trial(*session);
    if (is_trial) {
        LOG_ERR("A trial session cannot be used to authenticate, "
                "Please use an hmac or policy session");
        tpm2_session_close(session);
        return false;
    }

    return true;
}

static bool handle_file(ESYS_CONTEXT *ectx, const char *path, tpm2_session **session) {

    bool ret = false;

    TPM2B_AUTH auth = { 0 };

    UINT8 buffer[(sizeof(auth.buffer) * 2) + HEX_PREFIX_LEN + 1] = { 0 };
    UINT16 size = sizeof(buffer) - 1;

    path += FILE_PREFIX_LEN;

    path = strcmp("-", path) ? path : NULL;

    ret = files_load_bytes_from_buffer_or_file_or_stdin(NULL, path,
            &size, buffer);
    if (!ret) {
        return false;
    }

    ret = handle_password((char *)buffer, &auth);
    if (!ret) {
        return false;
    }

    *session = start_hmac_session(ectx, &auth);

    return *session != NULL;
}

static bool handle_pcr(ESYS_CONTEXT *ectx, const char *policy, tpm2_session **session) {

    policy += PCR_PREFIX_LEN;

    bool result = false;

    tpm2_session *s = NULL;

    char *dup = strdup(policy);
    if (!dup) {
        LOG_ERR("oom");
        return false;
    }

    const char *pcr_str = dup;
    const char *raw_path = NULL;
    char *split = strchr(dup, '+');
    if (split) {
        *split = '\0';
        raw_path = split + 1;
        raw_path = raw_path[0] == '\0' ? NULL : raw_path;
    }

    TPML_PCR_SELECTION pcrs;
    bool ret = pcr_parse_selections(pcr_str, &pcrs);
    if (!ret) {
        goto out;
    }

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        goto out;
    }

    s = tpm2_session_open(ectx, d);
    if (!s) {
        LOG_ERR("Could not start tpm session");
        goto out;
    }

    ret = tpm2_policy_build_pcr(ectx, s,
            raw_path, &pcrs);
    if (!ret) {
        goto out;
    }

    *session = s;

    result = true;

out:
    free(dup);

    /* if fail close session */
    if (!result) {
        tpm2_session_close(&s);
    }

    return result;
}

bool tpm2_auth_util_from_optarg(ESYS_CONTEXT *ectx, const char *password,
    tpm2_session **session, bool is_restricted) {

    bool result;

    password = password ? password : "";

    /* starts with session: */
    bool is_session = !strncmp(password, SESSION_PREFIX, SESSION_PREFIX_LEN);
    if (is_session) {

        if (is_restricted) {
            LOG_ERR("cannot specify %s", password);
            return false;
        }

        result = handle_session(ectx, password, session);
        if (!result) {
            return false;
        }
        goto handled;
    }

    /* starts with "file:" */
    bool is_file = !strncmp(password, FILE_PREFIX, FILE_PREFIX_LEN);
    if (is_file) {
        result = handle_file(ectx, password, session);
        if (!result) {
            return false;
        }
        goto handled;
    }

    /* starts with pcr: */
    bool is_pcr = !strncmp(password, PCR_PREFIX, PCR_PREFIX_LEN);
    if (is_pcr) {
        result = handle_pcr(ectx, password, session);
        if (!result) {
            return false;
        }
        goto handled;
    }

    /* must be a password */
    result = handle_password_session(ectx, password, session);
    if (!result) {
        return false;
    }

handled:

    return true;
}

ESYS_TR tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR object,
            tpm2_session *session) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    TPM2_RC rval = Esys_TR_SetAuth(ectx, object, auth);
    if (rval != TPM2_RC_SUCCESS) {
        return ESYS_TR_NONE;
    }

    return handle;
}
