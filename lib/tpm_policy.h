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

#ifndef SRC_POLICY_H_
#define SRC_POLICY_H_

//Records the type of policy and if one is selected
typedef struct {
        bool PolicyPCR;
        bool is_policy_type_selected;
}POLICY_TYPE;

//Common policy options
typedef struct {
	SESSION *policy_session; // policy session
	TPM_SE policy_session_type; // TPM_SE_TRIAL or TPM_SE_POLICY
    TPM2B_DIGEST policy_digest; // buffer to hold policy digest
    TPMI_ALG_HASH policy_digest_hash_alg; // hash alg of final policy digest
    bool extend_policy_session; // if policy session should persist
    char policy_file[PATH_MAX]; // filepath for the policy digest
    bool policy_file_flag; // if policy file input has been given
    POLICY_TYPE policy_type;
} COMMON_POLICY_OPTIONS;

//pcr policy options
typedef struct  {
	char raw_pcrs_file[PATH_MAX]; // filepath of input raw pcrs file  
    TPML_PCR_SELECTION pcr_selections; // records user pcr selection per setlist 
    bool is_set_list; // if user has provided the setlist choice  
    bool is_raw_pcrs_file; // if user has provided a raw pcrs file for policy calc
} PCR_POLICY_OPTIONS;

//policy options
typedef struct {
    TSS2_SYS_CONTEXT *sapi_context; // system API context from main
    COMMON_POLICY_OPTIONS common_policy_options; 
    PCR_POLICY_OPTIONS pcr_policy_options;
} CREATE_POLICY_CTX;

/**
 * Starts a policy session of the selected policy session type
 * @param pctx.common_policy_options.policy_session_type
 *  To start a TPM_SE_TRIAL or TPM_SE_POLICY policy session
 * @return
 *  TPM_RC_SUCCESS on success, not otherwise.
 */
TPM_RC start_policy_session (CREATE_POLICY_CTX *pctx);

/**
 * Extends PolicyPCR specifics into the policy digest of active session
 * Takes the input from raw pcr file or current pcr values.
 * @param pctx.common_policy_options.policy_session_type
 *  To start a TPM_SE_TRIAL or TPM_SE_POLICY policy session
 * @param pctx.pcr_policy_options.is_set_list
 *  To ensure user has selected the pcr indices across banks
 * @param pctx.pcr_policy_options.is_raw_pcrs and .raw_pcrs_file
 *  Records if a raw pcrs file has been given as as input and captures file path
 * @return
 *  TPM_RC_SUCCESS on success, not otherwise.
 */
TPM_RC build_pcr_policy(CREATE_POLICY_CTX *pctx);

/**
 * Calls start policy session, initiates specific policy type functions,
 * saves policy digest when in TRIAL mode and flushes context at end of operation
 * or keeps it alive depending upon the user choice.
 * @param pctx.common_policy_options.policy_session_type
 *  To start a TPM_SE_TRIAL or TPM_SE_POLICY policy session.
 * @return
 *  TPM_RC_SUCCESS on success, not otherwise.
 */
TPM_RC build_policy(CREATE_POLICY_CTX *pctx, TPM_RC (*build_policy_function)(CREATE_POLICY_CTX* pctx));

#endif /* SRC_POLICY_H_ */
