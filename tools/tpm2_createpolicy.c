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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "pcr.h"
#include "tpm2_util.h"
#include "tpm_session.h"
#include "tpm_hash.h"

//Records the type of policy and if one is selected
typedef struct {
    bool PolicyPCR;
    bool is_policy_type_selected;
}policy_type;

//Common policy options
typedef struct tpm2_common_policy_options tpm2_common_policy_options;
struct tpm2_common_policy_options {
    SESSION *policy_session; // policy session
    TPM_SE policy_session_type; // TPM_SE_TRIAL or TPM_SE_POLICY
    TPM2B_DIGEST policy_digest; // buffer to hold policy digest
    TPMI_ALG_HASH policy_digest_hash_alg; // hash alg of final policy digest
    bool extend_policy_session; // if policy session should persist
    char *policy_file; // filepath for the policy digest
    bool policy_file_flag; // if policy file input has been given
    policy_type policy_type;
};

//pcr policy options
typedef struct  tpm2_pcr_policy_options tpm2_pcr_policy_options;
struct tpm2_pcr_policy_options{
    char *raw_pcrs_file; // filepath of input raw pcrs file
    TPML_PCR_SELECTION pcr_selections; // records user pcr selection per setlist
    bool is_set_list; // if user has provided the setlist choice
};

typedef struct create_policy_ctx create_policy_ctx;
struct create_policy_ctx {
    TSS2_SYS_CONTEXT *sapi_context; // system API context from main
    tpm2_common_policy_options common_policy_options;
    tpm2_pcr_policy_options pcr_policy_options;
};

#define TPM2_COMMON_POLICY_INIT { \
            .policy_session = NULL, \
            .policy_session_type = TPM_SE_TRIAL, \
            .policy_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer), \
            .policy_digest_hash_alg = TPM_ALG_SHA256, \
        }

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

static TPM_RC build_pcr_policy(create_policy_ctx *pctx) {
    // Calculate digest( with authhash alg) of pcrvalues in variable pcr_digest
    TPM_RC rval=0;
    TPML_DIGEST pcr_values = {
        .count = 0
    };

    bool result = evaluate_populate_pcr_digests(pctx->pcr_policy_options.pcr_selections,
                                                pctx->pcr_policy_options.raw_pcrs_file,
                                                &pcr_values);
    if (!result) {
        return TPM_RC_NO_RESULT;
    }

    //If PCR input for policy is from raw pcrs file
    if (pctx->pcr_policy_options.raw_pcrs_file) {
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
    if (!pctx->pcr_policy_options.raw_pcrs_file) {
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
    TPM2B_DIGEST pcr_digest =  TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
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

static TPM_RC start_policy_session (create_policy_ctx *pctx) {
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

static TPM_RC build_policy(create_policy_ctx *pctx,
        TPM_RC (*build_policy_function)(create_policy_ctx *pctx)) {
    //Start policy session
    TPM_RC rval = start_policy_session(pctx);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Error starting the policy session.\n");
        return rval;
    }
    // Issue policy command.
    rval = (*build_policy_function)(pctx);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed parse_policy_type_and_send_command\n");
        return rval;
    }
    // Get Policy Hash
    rval = Tss2_Sys_PolicyGetDigest(pctx->sapi_context,
            pctx->common_policy_options.policy_session->sessionHandle, 0,
            &pctx->common_policy_options.policy_digest, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Failed Policy Get Digest\n");
        return rval;
    }

    // Need to flush the session here.
    if (!pctx->common_policy_options.extend_policy_session) {
        rval = Tss2_Sys_FlushContext(pctx->sapi_context,
                pctx->common_policy_options.policy_session->sessionHandle);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context\n");
            return rval;
        }

        // And remove the session from sessions table.
        rval = tpm_session_auth_end(pctx->common_policy_options.policy_session);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed deleting session from session table\n");
            return rval;
        }
    }

    return rval;
}

static TPM_RC parse_policy_type_specific_command (create_policy_ctx *pctx) {
    TPM_RC rval = TPM_RC_SUCCESS;
    if (!pctx->common_policy_options.policy_type.is_policy_type_selected){
        LOG_ERR("No Policy type chosen.\n");
        goto parse_policy_type_specific_command_error;
    }

    if (pctx->common_policy_options.policy_type.PolicyPCR) {
        //PCR inputs validation
        if (pctx->pcr_policy_options.is_set_list == false) {
            LOG_ERR("Need the pcr list to account for in the policy.");
            return TPM_RC_NO_RESULT;
        }
        
        rval = build_policy(pctx, build_pcr_policy);
        if (rval != TPM_RC_SUCCESS) {
            goto parse_policy_type_specific_command_error;
        }

        // Display the policy digest during real policy session.
        if (pctx->common_policy_options.policy_session_type == TPM_SE_POLICY) {
            printf("TPM_SE_POLICY: 0x");
            int i;
            for(i = 0; i < pctx->common_policy_options.policy_digest.t.size; i++) {
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
                return rval;
            }
        }
    }

    if (pctx->common_policy_options.extend_policy_session) {
        printf("EXTENDED_POLICY_SESSION_HANDLE: 0x%08X",
            pctx->common_policy_options.policy_session->sessionHandle );
    }

parse_policy_type_specific_command_error:
    return rval;
}

static bool init(int argc, char *argv[], create_policy_ctx *pctx) {
    struct option sOpts[] = {
        { "policy-file",    required_argument,  NULL,   'f' },
        { "policy-digest-alg", required_argument, NULL, 'g'},
        { "set-list",       required_argument,  NULL,   'L' },
        { "pcr-input-file", required_argument,  NULL,   'F' },
        { "policy-pcr",     no_argument,        NULL,   'P' },
        { "auth-policy-session", no_argument, NULL,     'a'},
        { "extend-policy-session", no_argument, NULL,   'e'},
        { NULL,             no_argument,        NULL,   '\0'},
    };
    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "f:g:L:F:Pae", sOpts, NULL)) != -1) {
        switch (opt) {
        case 'f':
            pctx->common_policy_options.policy_file_flag = true;
            pctx->common_policy_options.policy_file = optarg;
            break;
        case 'F':
            pctx->pcr_policy_options.raw_pcrs_file = optarg;
            break;
        case 'g':
            if (!tpm2_util_string_to_uint16(optarg,
                    &pctx->common_policy_options.policy_digest_hash_alg)) {
                showArgError(optarg, argv[0]);
                LOG_ERR("Invalid choice for policy digest hash algorithm\n");
                return false;
            }
            break;
        case 'L':
            if (!pcr_parse_selections(optarg,
                &pctx->pcr_policy_options.pcr_selections)) {
                showArgError(optarg, argv[0]);
                return false;
            }
            pctx->pcr_policy_options.is_set_list = true;
            break;
        case 'P':
            pctx->common_policy_options.policy_type.PolicyPCR = true;
            pctx->common_policy_options.policy_type.is_policy_type_selected= true;
            LOG_INFO("Policy type chosen is policyPCR.\n");
            break;
        case 'a':
            pctx->common_policy_options.policy_session_type = TPM_SE_POLICY;
            pctx->common_policy_options.extend_policy_session = true;
            LOG_INFO("Policy session setup for auth.\n");
            break;
        case 'e':
            pctx->common_policy_options.extend_policy_session = true;
            LOG_INFO("Policy session setup to extend after operation.\n");
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            return false;
        }
    }
    if (pctx->common_policy_options.policy_file_flag == false &&
        pctx->common_policy_options.policy_session_type == TPM_SE_TRIAL) {
        LOG_ERR("Provide the file name to store the resulting "
            "policy digest");
        return false;
    }
    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts and envp are unused */
    (void) opts;
    (void) envp;

    create_policy_ctx pctx = {
        .sapi_context = sapi_context,
        .common_policy_options = TPM2_COMMON_POLICY_INIT
    };

    bool result = init(argc, argv, &pctx);
    if (!result) {
        return 1;
    }

    TPM_RC rval = parse_policy_type_specific_command(&pctx);
    if (rval != TPM_RC_SUCCESS) {
        return 1;
    }

    /* true is success, coerce to 0 for program success */
    return 0;
}
