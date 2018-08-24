//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include "files.h"
#include "log.h"
#include "tpm2_hash.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_openssl.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

static bool evaluate_populate_pcr_digests(TPML_PCR_SELECTION *pcr_selections,
        const char *raw_pcrs_file, TPML_DIGEST *pcr_values) {

    unsigned expected_pcr_input_file_size = 0;
    unsigned dgst_cnt = 0;

    //Iterating the number of pcr banks selected
    UINT32 i;
    for (i = 0; i < pcr_selections->count; i++) {

        UINT8 total_indices_for_this_alg = 0;

        //Looping to check total pcr select bits in the pcr-select-octets for a bank
        UINT32 j;
        for (j = 0; j < pcr_selections->pcrSelections[i].sizeofSelect; j++) {
            UINT8 group_val = pcr_selections->pcrSelections[i].pcrSelect[j];
            total_indices_for_this_alg += tpm2_util_pop_count(group_val);
        }

        if(pcr_values->count + total_indices_for_this_alg > ARRAY_LEN(pcr_values->digests)) {
            LOG_ERR("Number of PCR is limited to %zu", ARRAY_LEN(pcr_values->digests));
            return false;
        }

        //digest size returned per the hashAlg type
        unsigned dgst_size = tpm2_alg_util_get_hash_size(
                pcr_selections->pcrSelections[i].hash);
        if (!dgst_size) {
            return false;
        }
        expected_pcr_input_file_size +=
                (total_indices_for_this_alg * dgst_size);

        //Cumulative total of all the pcr indices across banks selected in setlist
        pcr_values->count += total_indices_for_this_alg;

        /*
         * Populating the digest sizes in the PCR digest list per algorithm bank
         * Once iterated through all banks, creates an file offsets map for all pcr indices
         */
        UINT32 k;
        for (k = 0; k < total_indices_for_this_alg; k++) {
            pcr_values->digests[dgst_cnt + k].size = dgst_size;
        }
        dgst_cnt++;
    }

    //Check if the input pcrs file size is the same size as the pcr selection setlist
    if (raw_pcrs_file) {
        unsigned long filesize = 0;
        bool result = files_get_file_size_path(raw_pcrs_file, &filesize);
        if (!result) {
            LOG_ERR("Could not retrieve raw_pcrs_file size");
            return false;
        }
        if (filesize != expected_pcr_input_file_size) {
            LOG_ERR("pcr-input-file filesize does not match pcr set-list");
            return false;
        }
    }

    return true;
}

static bool tpm2_policy_pcr_build(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections) {

    TPML_DIGEST pcr_values = { .count = 0 };

    if (!pcr_selections->count) {
        LOG_ERR("No pcr selection data specified!");
        return false;
    }

    bool result = evaluate_populate_pcr_digests(pcr_selections, raw_pcrs_file,
            &pcr_values);
    if (!result) {
        return false;
    }

    //If PCR input for policy is from raw pcrs file
    if (raw_pcrs_file) {
        FILE *fp = fopen(raw_pcrs_file, "rb");
        if (fp == NULL) {
            LOG_ERR("Cannot open pcr-input-file %s", raw_pcrs_file);
            return false;
        }
        // Bank hashAlg values dictates the order of the list of digests
        unsigned i;
        for (i = 0; i < pcr_values.count; i++) {
            size_t sz = fread(&pcr_values.digests[i].buffer, 1,
                    pcr_values.digests[i].size, fp);
            if (sz != pcr_values.digests[i].size) {
                const char *msg =
                        ferror(fp) ? strerror(errno) : "end of file reached";
                LOG_ERR("Reading from file \"%s\" failed: %s", raw_pcrs_file,
                        msg);
                fclose(fp);
                return false;
            }
        }
        fclose(fp);
    } else {
        UINT32 pcr_update_counter;
        TPML_DIGEST *pcr_val = NULL;
        // Read PCRs
        TSS2_RC rval = Esys_PCR_Read(ectx,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        pcr_selections, &pcr_update_counter,
                        NULL, &pcr_val);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PCR_Read, rval);
            free(pcr_val);
            return false;
        }

        UINT32 i;
        pcr_val->count = pcr_values.count;
        for (i = 0; i < pcr_val->count; i++) {
            memcpy(pcr_values.digests[i].buffer, pcr_val->digests[i].buffer,
                    pcr_val->digests[i].size);
            pcr_values.digests[i].size = pcr_val->digests[i].size;
        }
        free(pcr_val);
    }

    // Calculate hashes
    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMI_ALG_HASH auth_hash = tpm2_session_get_authhash(policy_session);

    result = tpm2_openssl_hash_pcr_values(auth_hash,
                &pcr_values, &pcr_digest);
    if (!result) {
        LOG_ERR("Could not hash pcr values");
        return false;
    }

    // Call the PolicyPCR command
    ESYS_TR handle = tpm2_session_get_handle(policy_session);

    TSS2_RC rval = Esys_PolicyPCR(ectx, handle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &pcr_digest, pcr_selections);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyPCR, rval);
        return false;
    }

    return true;
}

bool tpm2_policy_build_pcr(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session,
        const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections) {

    // Issue policy command.
    bool result = tpm2_policy_pcr_build(ectx, policy_session,
            raw_pcrs_file, pcr_selections);

    if (!result) {
        LOG_ERR("Failed parse_policy_type_and_send_command");
    }

    return result;
}

bool tpm2_policy_build_policyauthorize(
    ESYS_CONTEXT *ectx,
    tpm2_session *policy_session,
    const char *policy_digest_path,
    const char *policy_qualifier_path,
    const char *verifying_pubkey_name_path,
    const char *ticket_path) {

    unsigned long file_size = 0;

    bool result = files_get_file_size_path(policy_digest_path, &file_size);
    if (!result) {
        return false;
    }

    TPM2B_DIGEST approved_policy = {
        .size = (uint16_t)file_size
    };
    result = files_load_bytes_from_path(policy_digest_path,
        approved_policy.buffer, &approved_policy.size);
    if (!result) {
        return false;
    }

    /*
     * Qualifier data is optional. If not specified default to 0
     */
    file_size = 0;
    if (policy_qualifier_path) {
        result = files_get_file_size_path(policy_qualifier_path,
            &file_size);
        if (!result) {
            return false;
        }
    }

    TPM2B_NONCE policy_qualifier = {
        .size = (uint16_t) file_size
    };

    if (file_size != 0) {
        result = files_load_bytes_from_path(policy_qualifier_path,
            policy_qualifier.buffer, &policy_qualifier.size);
        if (!result) {
            return false;
        }
    }

    result = files_get_file_size_path(verifying_pubkey_name_path, &file_size);
    if (!result) {
        return false;
    }

    if (!file_size) {
        LOG_ERR("Verifying public key name file \"%s\", cannot be empty",
                verifying_pubkey_name_path);
        return false;
    }

    TPM2B_NAME key_sign = {
        .size = (uint16_t)file_size
    };

    result = files_load_bytes_from_path(verifying_pubkey_name_path,
            key_sign.name,
        &key_sign.size);
    if (!result) {
        return false;
    }

    TPMT_TK_VERIFIED  check_ticket = {
        .tag = TPM2_ST_VERIFIED,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };
    result = tpm2_session_is_trial(policy_session);
    if (!result) {
        result = files_load_ticket(ticket_path, &check_ticket);
        if (!result) {
            LOG_ERR("Could not load verification ticket file");
            return false;
        }
    }

    ESYS_TR sess_handle = tpm2_session_get_handle(policy_session);
    TSS2_RC rval = Esys_PolicyAuthorize(ectx, sess_handle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &approved_policy, &policy_qualifier, &key_sign,
                    &check_ticket);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyAuthorize, rval);
        return false;
    }

    return true;
}

bool tpm2_policy_build_policyor(ESYS_CONTEXT *ectx,
    tpm2_session *policy_session, TPML_DIGEST policy_list) {

    ESYS_TR sess_handle = tpm2_session_get_handle(policy_session);
    TSS2_RC rval = Esys_PolicyOR(ectx, sess_handle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &policy_list);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyOR, rval);
        return false;
    }

    return true;
}

bool tpm2_policy_build_policypassword(ESYS_CONTEXT *ectx,
        tpm2_session *session) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(session);

    TSS2_RC rval = Esys_PolicyPassword(ectx, policy_session_handle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyPassword, rval);
        return false;
    }

    return true;
}

bool tpm2_policy_build_policysecret(ESYS_CONTEXT *ectx,
    tpm2_session *policy_session, TPMS_AUTH_COMMAND session_data,
    ESYS_TR handle) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(policy_session);
    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx, handle,
                        &session_data, policy_session);
    if (shandle == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return false;
    }
    TSS2_RC rval = Esys_PolicySecret(ectx, handle, policy_session_handle,
                    shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        return false;
    }

    return true;
}

bool tpm2_policy_get_digest(ESYS_CONTEXT *ectx,
        tpm2_session *session,
        TPM2B_DIGEST **policy_digest) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    TPM2_RC rval = Esys_PolicyGetDigest(ectx, handle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        policy_digest);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyGetDigest, rval);
        return false;
    }
    return true;
}

bool tpm2_policy_build_policycommandcode(ESYS_CONTEXT *ectx,
    tpm2_session *session, uint32_t command_code) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    TPM2_RC rval = Esys_PolicyCommandCode(ectx, handle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, command_code);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyCommandCode, rval);
        return false;
    }
    return true;
}

static bool tpm2_policy_populate_digest_list(char *buf, TPML_DIGEST *policy_list,
    TPMI_ALG_HASH hash) {

        uint8_t hash_len = tpm2_alg_util_get_hash_size(hash);
        if (!hash_len) {
            return false;
        }

        unsigned long file_size;
        bool retval = files_get_file_size_path(buf, &file_size);
        if (!retval) {
            return false;
        }
        if (file_size != hash_len) {
            return false;
        }

        policy_list->digests[policy_list->count].size = hash_len;
        /* All policy digests are expected to be of same hash len */
        if (policy_list->count > 0 &&
            policy_list->digests[policy_list->count].size !=
            policy_list->digests[policy_list->count - 1].size) {
            return false;
        }

        uint16_t policy_digest_size = hash_len;
        retval = files_load_bytes_from_path(buf, 
            policy_list->digests[policy_list->count].buffer, &policy_digest_size);
        if (!retval) {
            return false;
        }

        policy_list->count++;

        return true;
}

bool tpm2_policy_parse_policy_list(char *str, TPML_DIGEST *policy_list) {

    char *str1;
    char *str2;
    char *token;
    char *subtoken;
    char *saveptr1;
    char *saveptr2;
    const char *delimiter1 = ":";
    const char *delimiter2 = ",";

    unsigned int j;
    bool retval;
    TPMI_ALG_HASH hash = TPM2_ALG_ERROR;

    for (j = 1, str1 = str; ; j++, str1 = NULL) {

        token = strtok_r(str1, delimiter1, &saveptr1);
        if (token == NULL) {
            break;
        }

        for (str2 = token; ; str2 = NULL) {

            subtoken = strtok_r(str2, delimiter2, &saveptr2);
            if (subtoken == NULL) {
                break;
            }
            
            //Expecting one policy digest of same hash alg type for all policies
            if (j == 1) {
                hash = tpm2_alg_util_from_optarg(subtoken, tpm2_alg_util_flags_hash);
                if (hash == TPM2_ALG_ERROR) {
                    return false;
                }
            }

            //Multiple valid policy files
            if (j > 1) {
                retval = tpm2_policy_populate_digest_list(subtoken, policy_list, hash);
                if (!retval) {
                    return false;
                }
            }

        }
    }

    return true;
}
