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
#include "tpm_policy.h"

TPM_RC parse_policy_type_specific_command (CREATE_POLICY_CTX *pctx) {    
    TPM_RC rval = TPM_RC_SUCCESS;
    if (!pctx->common_policy_options.policy_type.is_policy_type_selected){
        LOG_ERR("No Policy type chosen.\n");
        goto parse_policy_type_specific_command_error;
    }
    
    if (pctx->common_policy_options.policy_type.PolicyPCR) { 
        rval = build_policy(pctx, build_pcr_policy);        
        if (rval != TPM_RC_SUCCESS) {            
            goto parse_policy_type_specific_command_error;
        }
    } 

    if (pctx->common_policy_options.extend_policy_session) {
        printf("EXTENDED_POLICY_SESSION_HANDLE: 0x%08X",
            pctx->common_policy_options.policy_session->sessionHandle );
    }

parse_policy_type_specific_command_error:
    return rval;
}

static bool init(int argc, char *argv[], CREATE_POLICY_CTX *pctx) {
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
    if (argc > (int) (2 * sizeof(sOpts) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "f:g:L:F:Pae", sOpts, NULL)) != -1) {
        switch (opt) {
        case 'f':
            pctx->common_policy_options.policy_file_flag = true;
            snprintf(pctx->common_policy_options.policy_file, 
                sizeof(pctx->common_policy_options.policy_file), "%s", optarg);
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
            if (pcr_parse_selections(optarg, 
                &pctx->pcr_policy_options.pcr_selections) != 0) {
                showArgError(optarg, argv[0]);
                return false;
            }
            pctx->pcr_policy_options.is_set_list = true;
            break;
        case 'F':
            pctx->pcr_policy_options.is_raw_pcrs_file = true;
            snprintf(pctx->pcr_policy_options.raw_pcrs_file, 
                sizeof(pctx->pcr_policy_options.raw_pcrs_file), "%s", optarg);
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

    CREATE_POLICY_CTX pctx = {
        .sapi_context = sapi_context,
        .common_policy_options = {
            .policy_session = NULL,
            .policy_session_type = TPM_SE_TRIAL,
            .policy_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
            .policy_digest_hash_alg = TPM_ALG_SHA256,
        }
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
