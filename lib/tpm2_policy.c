#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"

static unsigned get_size_from_alg(TPMI_ALG_HASH hashAlg) {
    switch (hashAlg) {
        case TPM_ALG_SHA1:
            return SHA1_DIGEST_SIZE;
        case TPM_ALG_SHA256:
            return SHA256_DIGEST_SIZE;
        case TPM_ALG_SHA384:
            return SHA384_DIGEST_SIZE;
        case TPM_ALG_SHA512:
            return SHA512_DIGEST_SIZE;
        case TPM_ALG_SM3_256:
            return SM3_256_DIGEST_SIZE;
        default:
            LOG_ERR("Unknown hashAlg, cannot determine digest size.\n");
            return 0;
    }
}

static bool evaluate_populate_pcr_digests(TPML_PCR_SELECTION pcr_selections,
                                          char *raw_pcrs_file,
                                          TPML_DIGEST *pcr_values) {
    //octet value of a pcr selection group
    uint8_t group_val=0;
    //total pcr indices per algorithm/ bank. Typically this is 24
    uint8_t total_indices_for_this_alg=0;
    //cumulative size total of selected indices per hashAlg
    unsigned expected_pcr_input_file_size=0;
    //loop counters
    unsigned i, j, k, dgst_cnt=0;
    const uint8_t bits_per_nibble[] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};

    //Iterating the number of pcr banks selected
    for (i=0; i < pcr_selections.count; i++) {
        //Looping to check total pcr select bits in the pcr-select-octets for a bank
        for (j=0; j < pcr_selections.pcrSelections[i].sizeofSelect; j++) {
            group_val = pcr_selections.pcrSelections[i].pcrSelect[j];
            total_indices_for_this_alg += bits_per_nibble[group_val & 0x0f];
            total_indices_for_this_alg += bits_per_nibble[group_val >> 4];
        }

        //digest size returned per the hashAlg type
        unsigned dgst_size = get_size_from_alg(pcr_selections.pcrSelections[i].hash);
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
    if (raw_pcrs_file) {
        unsigned long filesize = 0;
        bool result = files_get_file_size(raw_pcrs_file, &filesize);
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

TPM_RC tpm2_policy_pcr_build(TSS2_SYS_CONTEXT *sapi_context,
                             SESSION *policy_session,
                             TPML_PCR_SELECTION pcr_selections,
                             char *raw_pcrs_file) {
    // Calculate digest( with authhash alg) of pcrvalues in variable pcr_digest
    TPM_RC rval=0;
    TPML_DIGEST pcr_values = {
        .count = 0
    };

    bool result = evaluate_populate_pcr_digests(pcr_selections, raw_pcrs_file,
                                                &pcr_values);
    if (!result) {
        return TPM_RC_NO_RESULT;
    }

    //If PCR input for policy is from raw pcrs file
    if (raw_pcrs_file) {
        FILE *fp = fopen (raw_pcrs_file, "rb");
        if (fp == NULL) {
            LOG_ERR("Cannot open pcr-input-file %s", raw_pcrs_file);
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
                        raw_pcrs_file, msg);
                fclose(fp);
                return TPM_RC_NO_RESULT;
            }
        }
        fclose(fp);
    }

    //If PCR input for policy is to be read from the TPM
    if (!raw_pcrs_file) {
        UINT32 pcr_update_counter;
        TPML_PCR_SELECTION pcr_selection_out;
        // Read PCRs
        rval = Tss2_Sys_PCR_Read(sapi_context, 0,
            &pcr_selections,
            &pcr_update_counter, &pcr_selection_out, &pcr_values, 0);
        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }
    }

    // Calculate hashes
    TPM2B_DIGEST pcr_digest =  TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    rval = tpm_hash_sequence(sapi_context,
        policy_session->authHash, pcr_values.count,
        &pcr_values.digests[0], &pcr_digest);
    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }

    // Call the PolicyPCR command
    return Tss2_Sys_PolicyPCR(sapi_context, policy_session->sessionHandle,
                              0, &pcr_digest, &pcr_selections, 0);
}

static TPM_RC start_policy_session (TSS2_SYS_CONTEXT *sapi_context,
                                    SESSION **policy_session,
                                    TPM_SE policy_session_type,
                                    TPMI_ALG_HASH policy_digest_hash_alg) {
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM_ALG_NULL,
    };
    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;
    // Start policy session.
    TPM_RC rval = tpm_session_start_auth_with_params(sapi_context,
                                                     policy_session,
                                                     TPM_RH_NULL, 0,
                                                     TPM_RH_NULL, 0,
                                                     &nonceCaller,
                                                     &encryptedSalt,
                                                     policy_session_type,
                                                     &symmetric,
                                                     policy_digest_hash_alg);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed tpm session start auth with params\n");
    }
    return rval;
}

TPM_RC tpm2_policy_build(TSS2_SYS_CONTEXT *sapi_context,
                         SESSION **policy_session,
                         TPM_SE policy_session_type,
                         TPMI_ALG_HASH policy_digest_hash_alg,
                         TPML_PCR_SELECTION pcr_selections,
                         char *raw_pcrs_file,
                         TPM2B_DIGEST *policy_digest,
                         bool extend_policy_session,
        TPM_RC (*build_policy_function)(TSS2_SYS_CONTEXT *sapi_context,
                                        SESSION *policy_session,
                                        TPML_PCR_SELECTION pcr_selections,
                                        char *raw_pcrs_file)) {
    //Start policy session
    TPM_RC rval = start_policy_session(sapi_context, policy_session,
                                       policy_session_type,
                                       policy_digest_hash_alg);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Error starting the policy session.\n");
        return rval;
    }
    // Issue policy command.
    rval = (*build_policy_function)(sapi_context, *policy_session,
                                    pcr_selections, raw_pcrs_file);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed parse_policy_type_and_send_command\n");
        return rval;
    }
    // Get Policy Hash
    rval = Tss2_Sys_PolicyGetDigest(sapi_context,
                                    (*policy_session)->sessionHandle,
                                    0, policy_digest, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed Policy Get Digest\n");
        return rval;
    }

    // Need to flush the session here.
    if (!extend_policy_session) {
        rval = Tss2_Sys_FlushContext(sapi_context,
                                     (*policy_session)->sessionHandle);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context\n");
            return rval;
        }

        // And remove the session from sessions table.
        rval = tpm_session_auth_end(*policy_session);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed deleting session from session table\n");
            return rval;
        }
    }

    return rval;
}
