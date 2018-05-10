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
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_nv_util.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef enum tpm2_session_type tpm2_session_type;
enum tpm2_session_type {
    tpm2_session_fail = 0,
    tpm2_session_password,
    tpm2_session_hmac,
    tpm2_session_ea
};

#define HEX_PREFIX "hex:"
#define HEX_PREFIX_LEN (sizeof(HEX_PREFIX) - 1)

#define STR_PREFIX "str:"
#define STR_PREFIX_LEN (sizeof(STR_PREFIX) - 1)

#define HMAC_PREFIX "hmac:"
#define HMAC_PREFIX_LEN (sizeof(HMAC_PREFIX) - 1)

#define SESSION_PREFIX "session:"
#define SESSION_PREFIX_LEN (sizeof(SESSION_PREFIX) - 1)

#define PCR_PREFIX "pcr:"
#define PCR_PREFIX_LEN (sizeof(PCR_PREFIX) - 1)

static tpm2_session_type handle_hex(const char *password, TPMS_AUTH_COMMAND *auth) {

    auth->hmac.size = BUFFER_SIZE(typeof(auth->hmac), buffer);
    int rc = tpm2_util_hex_to_byte_structure(password, &auth->hmac.size, auth->hmac.buffer);
    if (rc) {
        auth->hmac.size = 0;
        return tpm2_session_fail;
    }

    return tpm2_session_password;
}

static tpm2_session_type copy_password(TPM2B_AUTH *hmac, const char *password) {
    /*
     * Per the man page:
     * "a return value of size or more means that the output was truncated."
     */
    size_t wrote = snprintf((char *)hmac->buffer, sizeof(hmac->buffer), "%s", password);
    if (wrote >= sizeof(hmac->buffer)) {
        hmac->size = 0;
        memset(hmac->buffer, 0, sizeof(hmac->buffer));
        return false;
    }

    hmac->size = wrote;
    return true;
}

static tpm2_session_type handle_hmac(TSS2_SYS_CONTEXT *sapi, const char *password, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session, tpm2_auth_cb *cb) {

    bool result = copy_password(&auth->hmac, password);
    if (!result) {
        return tpm2_session_fail;
    }

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_HMAC);
    if (!d) {
        LOG_ERR("Could not allocate new session data");
        return tpm2_session_fail;
    }

    if (cb && cb->hmac.init) {
        result = cb->hmac.init(d);
        if (!result) {
            LOG_ERR("hmac callback failed");
            tpm2_session_data_free(&d);
            return tpm2_session_fail;
        }
    }

    *session = tpm2_session_new(sapi, d);
    if (!*session) {
        LOG_ERR("Could not start new session");
        return tpm2_session_fail;
    }

    auth->sessionHandle = tpm2_session_get_handle(*session);

    return tpm2_session_hmac;
}

static tpm2_session_type handle_session(const char *path, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session) {

    *session = tpm2_session_restore(path);
    if (!*session) {
        return tpm2_session_fail;
    }

    auth->sessionHandle = tpm2_session_get_handle(*session);

    bool is_trial = tpm2_session_is_trial(*session);
    if (is_trial) {
        LOG_ERR("A trial session cannot be used to authenticate, "
                "Please use an hmac or policy session");
        tpm2_session_free(session);
        return tpm2_session_fail;
    }

    return tpm2_session_ea;
}

static tpm2_session_type handle_pcr(TSS2_SYS_CONTEXT *sapi, const char *spec, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session) {

    /*
     * Handle the parsing of a PCR spec which is pcr:f=<path> or pcr:p=<pcr spec>
     */
    TPML_PCR_SELECTION pcrs = { .count = 0 };
    const char *pcr_file = NULL;
    if (!strncmp(spec, "f=", 2)) {
        pcr_file = &spec[2];
    } else if(!strncmp(spec, "p=", 2)) {
        const char *pcr_spec = &spec[2];
        bool result = pcr_parse_selections(pcr_spec, &pcrs);
        if (!result) {
            LOG_ERR("Could not parse PCR selections, got: \"%s\"", pcr_spec);
            return tpm2_session_fail;
        }
    } else {
        LOG_ERR("Expected either a file (f=) or pcr (p=) based PCR spec,"
                "got: \"%s\"", spec);
        return tpm2_session_fail;
    }

    tpm2_session_data *d =
            tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        return tpm2_session_fail;
    }

    tpm2_session *s = tpm2_session_new(sapi, d);
    if (!s) {
        LOG_ERR("Could not start tpm session");
        return tpm2_session_fail;
    }

    bool result = tpm2_policy_build_pcr(sapi, s,
            pcr_file,
            &pcrs);
    if (!result) {
        LOG_ERR("Could not build a pcr policy");
        tpm2_session_free(&s);
        return tpm2_session_fail;
    }

    auth->sessionHandle = tpm2_session_get_handle(s);
    auth->sessionAttributes |= TPMA_SESSION_CONTINUESESSION;

    *session = s;
    return tpm2_session_ea;
}

static tpm2_session_type handle_str(const char *password, TPMS_AUTH_COMMAND *auth) {

    /* str may or may not have the str: prefix */
    bool is_str_prefix = !strncmp(password, STR_PREFIX, STR_PREFIX_LEN);
    if (is_str_prefix) {
        password += STR_PREFIX_LEN;
    }

    bool result = copy_password(&auth->hmac, password);
    return result ? tpm2_session_password : tpm2_session_fail;
}

tpm2_session_type tpm2_auth_util_from_optarg2(TSS2_SYS_CONTEXT *sapi, const char *password, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session, tpm2_auth_cb *cb) {

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (is_hex) {

        password += HEX_PREFIX_LEN;
        return handle_hex(password, auth);
    }

    bool is_session = !strncmp(password, SESSION_PREFIX, SESSION_PREFIX_LEN);
    if (is_session) {
        if (!session) {
            LOG_ERR("Tool does not support sessions for this auth value");
            return false;
        }

        password += SESSION_PREFIX_LEN;
        return handle_session(password, auth, session);
    }

    bool is_hmac = !strncmp(password, HMAC_PREFIX, HMAC_PREFIX_LEN);
    if (is_hmac) {
        if (!session) {
            LOG_ERR("Tool does not support HMAC for this auth value");
            return false;
        }

        password += HMAC_PREFIX_LEN;
        return handle_hmac(sapi, password, auth, session, cb);
    }

    bool is_pcr = !strncmp(password, PCR_PREFIX, PCR_PREFIX_LEN);
    if (is_pcr) {
        if (!session) {
            LOG_ERR("Tool does not support PCR for this auth value");
            return false;
        }

        password += PCR_PREFIX_LEN;
        return handle_pcr(sapi, password, auth, session);
    }
    /* must be string, handle it */
    return handle_str(password, auth);
}

bool tpm2_auth_util_from_optarg(const char *password, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session) {
    return tpm2_auth_util_from_optarg2(NULL, password, auth, session, NULL) != tpm2_session_fail;
}

bool tpm2_auth_util_from_options(TSS2_SYS_CONTEXT *sapi, tpm2_auth *auth, tpm2_auth_cb *cb,
        bool support_sessions) {

    if (!auth->cnt) {
        /*
         * default to the empty password.
         * The password and handle were set in the init macro.
         */
        auth->auth_list.count++;
        return true;
    }

    auth->cb = *cb;

    unsigned i;
    for (i=0; i < auth->cnt; i++) {

        const char *o = auth->optargs[i];
        TPMS_AUTH_COMMAND *a = &auth->auth_list.auths[i];
        tpm2_session **s = support_sessions ? &auth->sessions[i] : NULL;
        tpm2_session_type stype = tpm2_auth_util_from_optarg2(sapi, o, a, s, cb);
        if (stype == tpm2_session_fail) {
            tpm2_auth_util_free(sapi, auth);
            return false;
        } else if(stype == tpm2_session_hmac) {
            auth->hmac_indexes |= 1 << i;
        }

        auth->auth_list.count++;
    }

    return true;
}

bool tpm2_read_transient_persistent_obj_name(TSS2_SYS_CONTEXT *sapi_context,
    TPM2_HANDLE entity_handle, TPM2B_NAME *entity_name) {

    TPM2B_PUBLIC object_public;
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2_RC rval = TSS2_RETRY_EXP( Tss2_Sys_ReadPublic(sapi_context, entity_handle,
                                        NULL, &object_public, entity_name, &qualified_name,
                                        &sessions_data_out));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ReadPublic, rval);
        return false;
    }
    return true;
}

bool tpm2_hmac_auth_get_entity_name(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE entity_handle,
    TPM2B_NAME *entity_name) {

    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    bool res;
    uint8_t temp[4];
    unsigned i;
    //Get Entity names from handles
    switch(entity_handle & TPM2_HR_RANGE_MASK) {
        case TPM2_HR_NV_INDEX:
            res = tpm2_util_nv_read_public2(sapi_context,entity_handle, &nv_public,
                entity_name);
            if (!res) {
                LOG_ERR("Failed reading NV public when calculating name");
                return false;
            }
            break;
        case TPM2_HR_TRANSIENT:
        case TPM2_HR_PERSISTENT:
            res = tpm2_read_transient_persistent_obj_name(sapi_context,
                    entity_handle, entity_name);
            if (!res) {
                LOG_ERR("Failed reading Object public when calculating name");
                return false;
            }
            break;
        case TPM2_HR_PCR:
        case TPM2_HR_HMAC_SESSION:
        case TPM2_HR_POLICY_SESSION:
        case TPM2_HR_PERMANENT:
            entity_name->size = sizeof(TPM2_HANDLE);
            memcpy(temp, &entity_handle, sizeof(TPM2_HANDLE));
            for (i = 0; i < sizeof(TPM2_HANDLE); i++) {
               entity_name->name[i] = temp[3-i];
            }
            break;
        default:
            LOG_ERR("Handle not valid for HMAC auth");
            return false;
    }
    return true;
}

// TODO Figure out how I work and refactor me
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static bool command_authentication_hmac(tpm2_session *hmac_session, uint8_t *cp_hash,
    TPMS_AUTH_COMMAND *session_data, TPMS_AUTH_RESPONSE *response_data, char *optargs) {

    if (response_data->nonce.size) {
        tpm2_session_update_nonce_older(hmac_session, &response_data->nonce);
        session_data->hmac.size = strlen(optargs);
        memcpy(session_data->hmac.buffer,optargs,strlen(optargs));
    }

    const TPM2B_NONCE *nonce_tpm =
        tpm2_session_get_nonce_tpm(hmac_session);

    uint8_t *to_hmac_buffer = malloc(SHA256_DIGEST_LENGTH + nonce_tpm->size
                          + sizeof(TPMA_SESSION));
    if (!to_hmac_buffer) {
        LOG_ERR("oom");
        return false;
    }

    memcpy(to_hmac_buffer, cp_hash, SHA256_DIGEST_LENGTH);

    memcpy(to_hmac_buffer + SHA256_DIGEST_LENGTH, nonce_tpm->buffer, nonce_tpm->size);

    memcpy(to_hmac_buffer + SHA256_DIGEST_LENGTH + nonce_tpm->size,
           &session_data->sessionAttributes, sizeof(TPMA_SESSION));

    unsigned int temp_hash_len = 0;
    HMAC(EVP_sha256(), session_data->hmac.buffer, session_data->hmac.size,
        to_hmac_buffer, SHA256_DIGEST_LENGTH + nonce_tpm->size + sizeof(TPMA_SESSION),
        session_data->hmac.buffer, &temp_hash_len);
    session_data->hmac.size = temp_hash_len;
    free(to_hmac_buffer);

    return true;
}

uint8_t *get_cp_hash(TSS2_SYS_CONTEXT *sapi_context,
    TPM2B_NAME entity_1_name, TPM2B_NAME entity_2_name) {

    SHA256_CTX sha256;
    int is_success = SHA256_Init(&sha256);
    if (!is_success) {
        LOG_ERR("SHA256_Init failed when calculating HMAC");
        return NULL;
    }

    uint8_t cmd_code[4];
    TSS2_RC rval = Tss2_Sys_GetCommandCode(sapi_context, cmd_code);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_GetCommandCode, rval);
        return NULL;
    }

    is_success = SHA256_Update(&sha256, cmd_code, sizeof(cmd_code));
    if (!is_success) {
        LOG_ERR ("SHA256_Update failed when calculating HMAC");
        return NULL;
    }

    is_success = SHA256_Update(&sha256, entity_1_name.name, entity_1_name.size);
    if (!is_success) {
        LOG_ERR ("SHA256_Update failed when calculating HMAC");
        return NULL;
    }
    is_success = SHA256_Update(&sha256, entity_2_name.name, entity_2_name.size);
    if (!is_success) {
        LOG_ERR ("SHA256_Update failed when calculating HMAC");
        return NULL;
    }

    size_t command_params_size;
    const uint8_t *command_params;
    rval = Tss2_Sys_GetCpBuffer(sapi_context, &command_params_size, &command_params);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_GetCpBuffer, rval);
        return NULL;
    }

    is_success = SHA256_Update(&sha256, command_params, command_params_size);
    if (!is_success) {
        LOG_ERR ("SHA256_Update failed when calculating HMAC");
        return NULL;
    }

    uint8_t *cp_hash = malloc(SHA256_DIGEST_LENGTH);
    if (!cp_hash) {
        LOG_ERR ("OOM");
        return NULL;
    }

    is_success = SHA256_Final(cp_hash, &sha256);
    if (!is_success) {
        LOG_ERR ("SHA256_Final failed when calculating HMAC");
        free(cp_hash);
        return NULL;
    }

    return cp_hash;
}

static bool tpm2_hmac_auth_get_command_buffer_hmac(TSS2_SYS_CONTEXT *sapi_context, TPMS_AUTH_COMMAND *auth,
    tpm2_session *hmac_session, TPM2B_NAME entity_1_name,
    TPM2B_NAME entity_2_name, TPMS_AUTH_RESPONSE *response_data, char *optargs) {

    uint8_t *cp_hash = get_cp_hash(sapi_context, entity_1_name, entity_2_name);
    if (!cp_hash) {
        LOG_ERR("Command Parameter hash failed");
        return false;
    }

    command_authentication_hmac(hmac_session, cp_hash, auth, response_data, optargs);
    free(cp_hash);
    return true;
}

static bool tpm2b_auth_update_for_hmac(TSS2_SYS_CONTEXT *sapi,
        tpm2_auth_cb *cb, tpm2_session *s, TPMS_AUTH_COMMAND *a,
        void *udata, TPMS_AUTH_RESPONSE *response_data, char *optargs) {

    const TPM2_HANDLE *h = tpm2_session_get_auth_handles(s);

    unsigned i;
    TPM2B_NAME names[2];
    for (i=0; i < 2; i++) {
        bool result = tpm2_hmac_auth_get_entity_name(sapi, h[i], &names[i]);
        if (!result) {
            return false;
        }
    }

    if (cb && cb->hmac.update) {
        bool result = cb->hmac.update(sapi, udata);
        if (!result) {
            return false;
        }
    }

    return tpm2_hmac_auth_get_command_buffer_hmac(sapi, a, s, names[0], names[1],
            response_data, optargs);
}

bool tpm2b_auth_update(TSS2_SYS_CONTEXT *sapi, tpm2_auth *auth, void *udata) {

    unsigned i;
    for (i=0; i < auth->cnt; i++) {
        if (auth->hmac_indexes & (1 << i)) {
            bool result = tpm2b_auth_update_for_hmac(sapi, &auth->cb,
                    auth->sessions[i], &auth->auth_list.auths[i], udata,
                    &auth->resp_list.auths[i], (char *)auth->optargs[i]+HMAC_PREFIX_LEN);
            if (!result) {
                return false;
            }
        }
    }

    return true;
}

bool tpm2_auth_util_free(TSS2_SYS_CONTEXT *sapi, tpm2_auth *auth) {

    bool result = true;
    unsigned i;
    for (i=0; i < auth->cnt; i++) {
        tpm2_session *s = auth->sessions[i];
        if (s) {
            result &= tpm2_session_close(sapi, s);
            tpm2_session_free(&s);
        }
    }

    return result;
}
