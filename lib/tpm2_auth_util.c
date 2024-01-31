/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_policy.h"
#include "tpm2_alg_util.h"
#include "tpm2_capability.h"

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

static struct termios old;

/* When the program is interrupted during callbacks,
 * restore the old termios state (with ICANON and ECHO) */
static void signal_termio_restore(__attribute__((unused)) int signumber) {
    tcsetattr (STDIN_FILENO, TCSANOW, &old);
}

static bool handle_hex_password(const char *password, TPM2B_AUTH *auth) {

    /* if it is hex, then skip the prefix */
    password += HEX_PREFIX_LEN;

    auth->size = BUFFER_SIZE(typeof(*auth), buffer);
    int rc = tpm2_util_hex_to_byte_structure(password, &auth->size,
            auth->buffer);
    if (rc) {
        auth->size = 0;
        return false;
    }

    return true;
}

bool handle_password(const char *password, TPM2B_AUTH *auth);

static tool_rc get_auth_for_file_param(const char* password, TPM2B_AUTH *auth) {
    const char* path = password;
    size_t size = (sizeof(auth->buffer) * 2) + HEX_PREFIX_LEN + 2;
    bool is_a_tty = isatty(STDIN_FILENO);

    /* Allocating one extra byte for \0 termination safety */
    UINT8 *buffer = calloc(1, size + 1);
    if (!buffer) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }
    buffer[size] = '\0';

    if (path) {
        path = strcmp("-", path) ? path : NULL;
    }
    if (!is_a_tty || path) {
        UINT16 fsize = size - 1;
        bool ret = files_load_bytes_from_buffer_or_file_or_stdin(NULL, path,
                                                                 &fsize, buffer);
        if (!ret) {
            free(buffer);
            return tool_rc_general_error;
        }
        size = fsize;

    } else {
        /*
         * It is a TTY and we're reading from stdin.
         * Prompt the user for the password with echoing
         * disabled.
         */
        struct termios new;
        tcgetattr (STDIN_FILENO, &old);
        new = old;
        new.c_lflag &= ~(ICANON | ECHO);
        struct sigaction signal_action;
        memset (&signal_action, 0, sizeof signal_action);
        signal_action.sa_handler = signal_termio_restore;
        sigaction (SIGTERM, &signal_action, NULL);
        sigaction (SIGINT, &signal_action, NULL);
        tcsetattr (STDIN_FILENO, TCSANOW, &new);

        printf("Enter Password: ");
        fflush(stdout);

        ssize_t read = getline((char **)&buffer, &size, stdin);

        tcsetattr (STDIN_FILENO, TCSANOW, &old);
        signal_action.sa_handler = SIG_DFL;
        sigaction (SIGTERM, &signal_action, NULL);
        sigaction (SIGINT, &signal_action, NULL);

        if (read < 0) {
            LOG_ERR("Could not get stdin, error: \"%s\"", strerror(errno));
            free(buffer);
            return tool_rc_general_error;
        }
        size = read;
    }

    /* bash here strings and many commands add a trailing newline, if its stdin, kill the newline */
    size_t i;
    for (i = size; i >=  1; i -= 1) {
        if (buffer[i - 1] == '\n' || buffer[i - 1] == '\r') {
            buffer[i - 1] = '\0';
        } else {
            break;
        }
    }
    /* from here the buffer has been populated with the password */
    bool ret = handle_password((char *) buffer, auth);
    if (!ret) {
        free(buffer);
        return tool_rc_general_error;
    }
    free(buffer);
    return tool_rc_success;
}

bool handle_str_password(const char *password, TPM2B_AUTH *auth) {

    /* str may or may not have the str: prefix */
    bool is_str_prefix = !strncmp(password, STR_PREFIX, STR_PREFIX_LEN);
    if (is_str_prefix) {
        password += STR_PREFIX_LEN;
    }

    /*
     * Per the man page:
     * "a return value of size or more means that the output was truncated."
     */
    size_t wrote = snprintf((char * )&auth->buffer,
            BUFFER_SIZE(typeof(*auth), buffer), "%s", password);
    if (wrote >= BUFFER_SIZE(typeof(*auth), buffer)) {
        auth->size = 0;
        return false;
    }

    auth->size = wrote;

    return true;
}

bool handle_password(const char *password, TPM2B_AUTH *auth) {

    bool is_file = !strncmp(password, FILE_PREFIX, FILE_PREFIX_LEN);

    if (is_file) {
        tool_rc rc = get_auth_for_file_param(password + FILE_PREFIX_LEN, auth);
        if (rc != tool_rc_success) {
            LOG_ERR("get password");
            return false;
        }
        return true;
    }

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (is_hex) {
        return handle_hex_password(password, auth);
    }

    /* must be string, handle it */
    return handle_str_password(password, auth);
}

static tool_rc start_hmac_session(ESYS_CONTEXT *ectx, TPM2B_AUTH *auth,
        tpm2_session **session) {

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_HMAC);
    if (!d) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    if (ectx) {
        uint32_t i;
        tool_rc tmp_rc;
        TPM2_CAP capability = TPM2_CAP_ALGS;
        UINT32 property = 0;
        UINT32 count = TPM2_MAX_CAP_ALGS;
        TPMS_CAPABILITY_DATA *capability_data = NULL;
        TPMS_ALG_PROPERTY alg_property;
        TPMI_ALG_HASH def_hash = tpm2_session_data_get_authhash(d);
        TPMI_ALG_HASH hash = 0;
        UINT16 hash_size = 0;

        tmp_rc = tpm2_capability_get(ectx, capability, property, count, &capability_data);
        if (tmp_rc == tool_rc_success) {
            for (i = 0; i < capability_data->data.algorithms.count; i++) {
                alg_property = capability_data->data.algorithms.algProperties[i];
                if ((alg_property.algProperties & TPMA_ALGORITHM_HASH) &&
                        !(alg_property.algProperties & ~(TPMA_ALGORITHM_HASH))) {
                    if (alg_property.alg == def_hash) {
                        break;
                    }
                    if (tpm2_alg_util_get_hash_size(alg_property.alg) > hash_size) {
                        hash = alg_property.alg;
                        hash_size = tpm2_alg_util_get_hash_size(alg_property.alg);
                    }
                }
            }
            if (hash_size > 0 && i == capability_data->data.algorithms.count) {
                tpm2_session_set_authhash(d, hash);
            }
            free(capability_data);
        }
    }

    tool_rc rc = tpm2_session_open(ectx, d, session);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_session_set_auth_value(*session, auth);

    return tool_rc_success;
}

static tool_rc handle_password_session(ESYS_CONTEXT *ectx, const char *password,
        tpm2_session **session) {

    TPM2B_AUTH auth = { 0 };
    bool result = handle_password(password, &auth);
    if (!result) {
        return tool_rc_general_error;
    }

    return start_hmac_session(ectx, &auth, session);
}

static tool_rc handle_session(ESYS_CONTEXT *ectx, const char *path,
        tpm2_session **session) {

    TPM2B_AUTH auth = { 0 };

    /* if it is session, then skip the prefix */
    path += SESSION_PREFIX_LEN;

    /* Make a local copy for manipulation */
    char tmp[PATH_MAX];
    size_t len = snprintf(tmp, sizeof(tmp), "%s", path);
    if (len >= sizeof(tmp)) {
        LOG_ERR("Path truncated");
        return tool_rc_general_error;
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
                return tool_rc_general_error;
            }
        }
    }

    tool_rc rc = tpm2_session_restore(ectx, tmp, false, session);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_session_set_auth_value(*session, &auth);

    bool is_trial = tpm2_session_is_trial(*session);
    if (is_trial) {
        LOG_ERR("A trial session cannot be used to authenticate, "
                "Please use an hmac or policy session");
        tpm2_session_close(session);
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static bool parse_pcr(const char *policy, char **pcr_str, char **raw_path) {
    char *split;

    policy += PCR_PREFIX_LEN;

    *pcr_str = NULL;
    *raw_path = NULL;

    /* completely empty PCR specification or just raw-pcr-file given */
    if ((policy[0] == '\0') || (policy[0] == '=')) {
       return false;
    }

    *pcr_str = strdup(policy);
    if (!*pcr_str) {
        LOG_ERR("oom");
        return false;
    }

    split = strchr(*pcr_str, '=');
    if (split) {
        split[0] = '\0';
        *raw_path = split + 1;

        /* empty raw-pcr-file */
        if (*raw_path[0] == '\0') {
            return false;
        }
    }

    return true;
}

static tool_rc handle_pcr(ESYS_CONTEXT *ectx, const char *policy,
        tpm2_session **session) {
    tool_rc rc = tool_rc_general_error;

    char *pcr_str, *raw_path;
    TPML_PCR_SELECTION pcrs;
    bool ret;

    ret = parse_pcr(policy, &pcr_str, &raw_path);
    if (!ret) {
        goto out;
    }

    ret = pcr_parse_selections(pcr_str, &pcrs, NULL);
    if (!ret) {
        goto out;
    }

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        goto out;
    }

    if (ectx) {
        uint32_t i;
        tool_rc tmp_rc;
        TPM2_CAP capability = TPM2_CAP_ALGS;
        UINT32 property = 0;
        UINT32 count = TPM2_MAX_CAP_ALGS;
        TPMS_CAPABILITY_DATA *capability_data = NULL;
        TPMS_ALG_PROPERTY alg_property;
        TPMI_ALG_HASH def_hash = tpm2_session_data_get_authhash(d);
        TPMI_ALG_HASH hash = 0;
        UINT16 hash_size = 0;

        tmp_rc = tpm2_capability_get(ectx, capability, property, count, &capability_data);
        if (tmp_rc == tool_rc_success) {
            for (i = 0; i < capability_data->data.algorithms.count; i++) {
                alg_property = capability_data->data.algorithms.algProperties[i];
                if ((alg_property.algProperties & TPMA_ALGORITHM_HASH) &&
                        !(alg_property.algProperties & ~(TPMA_ALGORITHM_HASH))) {
                    if (alg_property.alg == def_hash) {
                        break;
                    }
                    if (tpm2_alg_util_get_hash_size(alg_property.alg) > hash_size) {
                        hash = alg_property.alg;
                        hash_size = tpm2_alg_util_get_hash_size(alg_property.alg);
                    }
                }
            }
            if (hash_size > 0 && i == capability_data->data.algorithms.count) {
                tpm2_session_set_authhash(d, hash);
            }
            free(capability_data);
        }
    }

    tpm2_session *s = NULL;
    tool_rc tmp_rc = tpm2_session_open(ectx, d, &s);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Could not start tpm session");
        rc = tmp_rc;
        goto out;
    }

    tmp_rc = tpm2_policy_build_pcr(ectx, s, raw_path, &pcrs, NULL, NULL);
    if (tmp_rc != tool_rc_success) {
        tpm2_session_close(&s);
        rc = tmp_rc;
        goto out;
    }

    *session = s;
    rc = tool_rc_success;

out:
    free(pcr_str);

    return rc;
}

static tool_rc handle_file(ESYS_CONTEXT *ectx, const char *path,
        tpm2_session **session) {

    path += FILE_PREFIX_LEN;
    path = strcmp("-", path) ? path : NULL;
    TPM2B_AUTH auth = { 0 };

    tool_rc rc = get_auth_for_file_param(path, &auth);

    if (rc != tool_rc_success) {
        LOG_ERR("get password");
        return rc;
    }
    return start_hmac_session(ectx, &auth, session);
}

tool_rc tpm2_auth_util_from_optarg(ESYS_CONTEXT *ectx, const char *password,
        tpm2_session **session, bool is_restricted) {

    password = password ? password : "";

    /* starts with session: */
    bool is_session = !strncmp(password, SESSION_PREFIX, SESSION_PREFIX_LEN);
    if (is_session) {

        if (is_restricted) {
            LOG_ERR("Cannot specify password type \"session:\"");
            return tool_rc_general_error;
        }

        return handle_session(ectx, password, session);
    }

    /* starts with "file:" */
    bool is_file = !strncmp(password, FILE_PREFIX, FILE_PREFIX_LEN);
    if (is_file) {
        return handle_file(ectx, password, session);
    }

    /* starts with pcr: */
    bool is_pcr = !strncmp(password, PCR_PREFIX, PCR_PREFIX_LEN);
    if (is_pcr) {
        if (is_restricted) {
            LOG_ERR("Cannot specify password type \"pcr:\"");
            return tool_rc_general_error;
        }
        return handle_pcr(ectx, password, session);
    }

    /* must be a password */
    return handle_password_session(ectx, password, session);
}

tool_rc tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR object,
        tpm2_session *session, ESYS_TR *out) {

    *out = tpm2_session_get_handle(session);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    return tpm2_tr_set_auth(ectx, object, auth);
}
