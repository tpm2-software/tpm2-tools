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

static bool tpm2_policy_pcr_build(TSS2_SYS_CONTEXT *sapi_context,
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
        TPML_PCR_SELECTION pcr_selection_out;
        // Read PCRs
        TSS2_RC rval = Tss2_Sys_PCR_Read(sapi_context, NULL, pcr_selections,
                &pcr_update_counter, &pcr_selection_out, &pcr_values, NULL);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_PCR_Read, rval);
            return false;
        }
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
    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(
            policy_session);

    TSS2_RC rval = Tss2_Sys_PolicyPCR(sapi_context, handle,
    NULL, &pcr_digest, pcr_selections, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyPCR, rval);
        return false;
    }

    return true;
}

bool tpm2_policy_build_pcr(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session *policy_session,
        const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections) {

    // Issue policy command.
    bool result = tpm2_policy_pcr_build(sapi_context, policy_session,
            raw_pcrs_file, pcr_selections);

    if (!result) {
        LOG_ERR("Failed parse_policy_type_and_send_command");
    }

    return result;
}

bool tpm2_policy_get_digest(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session *session,
        TPM2B_DIGEST *policy_digest) {

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(session);

    TPM2_RC rval = Tss2_Sys_PolicyGetDigest(sapi_context, handle,
    NULL, policy_digest, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyGetDigest, rval);
        return false;
    }
    return true;
}

