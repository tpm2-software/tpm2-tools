//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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
#include <string.h>

#include <tss2/tss2_sys.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "log.h"
#include "tpm2_error.h"
#include "tpm2_nv_util.h"
#include "tpm2_openssl.h"
#include "tpm2_session.h"

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
            res = tpm2_util_nv_read_public(sapi_context,entity_handle, &nv_public,
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

static bool command_authentication_hmac(tpm2_session *hmac_session, uint8_t *cp_hash,
    TPMS_AUTH_COMMAND *session_data) {

    TPM2B_NONCE *nonce_tpm =
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

bool tpm2_hmac_auth_get_command_buffer_hmac(TSS2_SYS_CONTEXT *sapi_context,
    TPM2_HANDLE auth_handle, tpm2_session *hmac_session,
    TPMS_AUTH_COMMAND *session_data, TPM2B_NAME entity_1_name,
    TPM2B_NAME entity_2_name) {

    if (!auth_handle) {
        LOG_ERR("Authentication handle cannot be NULL");
        return false;
    }

    uint8_t *cp_hash = get_cp_hash(sapi_context, entity_1_name, entity_2_name);
    if (!cp_hash) {
        LOG_ERR("Command Parameter hash failed");
        return false;
    }

    command_authentication_hmac(hmac_session, cp_hash, session_data);
    free(cp_hash);
    return true;
}

