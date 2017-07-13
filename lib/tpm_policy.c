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

#include "files.h"
#include "log.h"
#include "tpm_hash.h"
#include "tpm_session.h"
#include "tpm_policy.h"
#include "tpm2_util.h"

static unsigned get_size_from_alg(TPMI_ALG_HASH hashAlg) {
    switch (hashAlg) {
        case TPM_ALG_SHA1:
            return SHA1_DIGEST_SIZE;
            break;
        case TPM_ALG_SHA256:
            return SHA256_DIGEST_SIZE;
            break;
        case TPM_ALG_SHA384:
            return SHA384_DIGEST_SIZE;
            break;
        case TPM_ALG_SHA512:
            return SHA512_DIGEST_SIZE;
            break;
        case TPM_ALG_SM3_256:
            return SM3_256_DIGEST_SIZE;
            break;
        default:
            LOG_ERR("Unknown hashAlg, cannot determine digest size.\n");
            return 0;
    }
}

static bool evaluate_populate_pcr_digests(CREATE_POLICY_CTX *pctx, TPML_DIGEST *pcr_values) {
    //octet value of a pcr selection group
    uint8_t group_val=0; 
    //total pcr indices per algorithm/ bank. Typically this is 24
    uint8_t total_indices_for_this_alg=0; 
    //cumulative size total of selected indices per hashAlg
    unsigned expected_pcr_input_file_size=0;
    //loop counters
    unsigned i, j, k, dgst_cnt=0; 

    //Iterating the number of pcr banks selected
    for (i=0; i < pctx->pcr_policy_options.pcr_selections.count; i++) { 
        //Looping to check total pcr select bits in the pcr-select-octets for a bank
        for (j=0; j < pctx->pcr_policy_options.pcr_selections.pcrSelections[i].sizeofSelect; j++) {
            group_val = pctx->pcr_policy_options.pcr_selections.pcrSelections[i].pcrSelect[j];
            total_indices_for_this_alg += ( ((group_val>>3) & 1) + ((group_val>>2) & 1) +
                ((group_val>>1) &1 ) + (group_val & 1) );
        }

        //digest size returned per the hashAlg type 
        unsigned dgst_size = get_size_from_alg(pctx->pcr_policy_options.pcr_selections.pcrSelections[i].hash);
        if (!dgst_size) {
            return false;
        }
        expected_pcr_input_file_size += (total_indices_for_this_alg * dgst_size);
  
        //Cumulative total of all the pcr indices across banks selected in setlist 
        pcr_values->count += total_indices_for_this_alg;

        /*
         * Populating the digest sizes in the PCR digest list per algorithm bank 
         * Once iterated through all banks, creates an file offsets map for all pcr indices
         */
        for (k=0; k < total_indices_for_this_alg; k++) {
            pcr_values->digests[dgst_cnt+k].t.size = dgst_size;
        }
        dgst_cnt++;

        total_indices_for_this_alg=0;
    }

    //Check if the input pcrs file size is the same size as the pcr selection setlist 
    if (pctx->pcr_policy_options.is_raw_pcrs_file) {
        long filesize = 0;
        bool result = files_get_file_size(pctx->pcr_policy_options.raw_pcrs_file, &filesize);
        if (!result) {
            LOG_ERR("Could not retrieve raw_pcrs_file size\n");
            return false;
        }
        if (filesize != expected_pcr_input_file_size) {
            LOG_ERR("pcr-input-file filesize does not match pcr set-list");
            return false;
        } 
    } 

    return true;
}

TPM_RC build_pcr_policy(CREATE_POLICY_CTX *pctx) {
    //PCR inputs validation
    if (pctx->pcr_policy_options.is_set_list == false) {
        LOG_ERR("Need the pcr list to account for in the policy.");
        return TPM_RC_NO_RESULT;
    }

    // Calculate digest( with authhash alg) of pcrvalues in variable pcr_digest
    TPM_RC rval=0;
    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPML_DIGEST pcr_values = {
        .count = 0
    };

    bool result = evaluate_populate_pcr_digests(pctx, &pcr_values);
    if (!result) {
        return TPM_RC_NO_RESULT;
    } 

    //If PCR input for policy is from raw pcrs file
    if (pctx->pcr_policy_options.is_raw_pcrs_file) {
        FILE *fp = fopen (pctx->pcr_policy_options.raw_pcrs_file, "rb");
        if (fp == NULL) {
            LOG_ERR("Cannot open pcr-input-file %s", pctx->pcr_policy_options.raw_pcrs_file);
            return TPM_RC_NO_RESULT;
        }
       // Bank hashAlg values dictates the order of the list of digests
        unsigned i;
        for(i=0; i<pcr_values.count; i++) {
            size_t sz = fread(&pcr_values.digests[i].t.buffer, 1, pcr_values.digests[i].t.size, fp);
            if (sz != pcr_values.digests[i].t.size) {
                const char *msg = ferror(fp) ? strerror(errno) :
                        "end of file reached";
                LOG_ERR("Reading from file \"%s\" failed: %s",
                        pctx->pcr_policy_options.raw_pcrs_file, msg);
                fclose(fp);
                return TPM_RC_NO_RESULT;
            }
        }
        fclose(fp);
    } 

    //If PCR input for policy is to be read from the TPM
    if (!pctx->pcr_policy_options.is_raw_pcrs_file) {
        UINT32 pcr_update_counter;
        TPML_PCR_SELECTION pcr_selection_out;
        // Read PCRs
        rval = Tss2_Sys_PCR_Read(pctx->sapi_context, 0, 
            &pctx->pcr_policy_options.pcr_selections, 
            &pcr_update_counter, &pcr_selection_out, &pcr_values, 0);
        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }
    }
    // Calculate hashes
    rval = tpm_hash_sequence(pctx->sapi_context, 
        pctx->common_policy_options.policy_session->authHash, pcr_values.count, 
        &pcr_values.digests[0], &pcr_digest);
    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }
    // Call the PolicyPCR command
    return Tss2_Sys_PolicyPCR(pctx->sapi_context,
            pctx->common_policy_options.policy_session->sessionHandle, 0, 
            &pcr_digest, &pctx->pcr_policy_options.pcr_selections, 0);
}

TPM_RC start_policy_session (CREATE_POLICY_CTX *pctx) {
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPMT_SYM_DEF symmetric = { 
        .algorithm = TPM_ALG_NULL, 
    };
    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;
    // Start policy session.
    TPM_RC rval = tpm_session_start_auth_with_params(pctx->sapi_context,
            &pctx->common_policy_options.policy_session, TPM_RH_NULL, 0, 
            TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, 
            pctx->common_policy_options.policy_session_type, &symmetric, 
            pctx->common_policy_options.policy_digest_hash_alg);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed tpm session start auth with params\n");
    }
    return rval;
}

TPM_RC build_policy(CREATE_POLICY_CTX *pctx,
        TPM_RC (*build_policy_function)(CREATE_POLICY_CTX *pctx)) {    
    //Start policy session
    TPM_RC rval = start_policy_session(pctx);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Error starting the policy session.\n");
        goto build_policy_error;
    }
    // Issue policy command.
    rval = (*build_policy_function)(pctx);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed parse_policy_type_and_send_command\n");
        goto build_policy_error;
    }
    // Get Policy Hash
    rval = Tss2_Sys_PolicyGetDigest(pctx->sapi_context,
            pctx->common_policy_options.policy_session->sessionHandle, 0, 
            &pctx->common_policy_options.policy_digest, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed Policy Get Digest\n");
        goto build_policy_error;
    } 
    // Display the policy digest during real policy session.
    if (pctx->common_policy_options.policy_session_type == TPM_SE_POLICY) {
        printf("TPM_SE_POLICY: 0x");
        int i;
        for(i=0; i<pctx->common_policy_options.policy_digest.t.size; i++) {
            printf("%02X", pctx->common_policy_options.policy_digest.t.buffer[i]);
        }
        printf("\n");
    }
    // Additional operations when session if a trial policy session
    if (pctx->common_policy_options.policy_session_type == TPM_SE_TRIAL) {
        //save the policy buffer in a file for use later
        bool result = files_save_bytes_to_file(pctx->common_policy_options.policy_file, 
            (UINT8 *) &pctx->common_policy_options.policy_digest.t.buffer, 
            pctx->common_policy_options.policy_digest.t.size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    pctx->common_policy_options.policy_file);
            rval = TPM_RC_NO_RESULT;
            goto build_policy_error;
        }
    }
    // Need to flush the session here.
    if (!pctx->common_policy_options.extend_policy_session) {
        rval = Tss2_Sys_FlushContext(pctx->sapi_context,
                pctx->common_policy_options.policy_session->sessionHandle);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context\n");
            goto build_policy_error;
        }             
    } 
    // And remove the session from sessions table.
    rval = tpm_session_auth_end(pctx->common_policy_options.policy_session);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed deleting session from session table\n");        
        goto build_policy_error;
    }

build_policy_error:
    return rval;
}