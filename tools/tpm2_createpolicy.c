//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_policy.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

//Records the type of policy and if one is selected
typedef struct {
    bool PolicyPCR;
    bool is_policy_type_selected;
}policy_type;

//Common policy options
typedef struct tpm2_common_policy_options tpm2_common_policy_options;
struct tpm2_common_policy_options {
    SESSION *policy_session; // policy session
    TPM2_SE policy_session_type; // TPM2_SE_TRIAL or TPM2_SE_POLICY
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
    tpm2_common_policy_options common_policy_options;
    tpm2_pcr_policy_options pcr_policy_options;
};

#define TPM2_COMMON_POLICY_INIT { \
            .policy_session = NULL, \
            .policy_session_type = TPM2_SE_TRIAL, \
            .policy_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer), \
            .policy_digest_hash_alg = TPM2_ALG_SHA256, \
        }

static create_policy_ctx pctx = {
    .common_policy_options = TPM2_COMMON_POLICY_INIT
};

static TSS2_RC parse_policy_type_specific_command(TSS2_SYS_CONTEXT *sapi_context) {
    TSS2_RC rval = TPM2_RC_SUCCESS;
    if (!pctx.common_policy_options.policy_type.is_policy_type_selected){
        LOG_ERR("No Policy type chosen.");
        return rval;
    }

    if (pctx.common_policy_options.policy_type.PolicyPCR) {
        //PCR inputs validation
        if (pctx.pcr_policy_options.is_set_list == false) {
            LOG_ERR("Need the pcr list to account for in the policy.");
            return TPM2_RC_NO_RESULT;
        }
        rval = tpm2_policy_build(sapi_context,
                                 &pctx.common_policy_options.policy_session,
                                 pctx.common_policy_options.policy_session_type,
                                 pctx.common_policy_options.policy_digest_hash_alg,
                                 &pctx.pcr_policy_options.pcr_selections,
                                 pctx.pcr_policy_options.raw_pcrs_file,
                                 &pctx.common_policy_options.policy_digest,
                                 pctx.common_policy_options.extend_policy_session,
                                 tpm2_policy_pcr_build);
        if (rval != TPM2_RC_SUCCESS) {
            return rval;
        }

        // Display the policy digest during real policy session.
        if (pctx.common_policy_options.policy_session_type == TPM2_SE_POLICY) {
            tpm2_tool_output("TPM2_SE_POLICY: 0x");
            int i;
            for(i = 0; i < pctx.common_policy_options.policy_digest.size; i++) {
                tpm2_tool_output("%02X", pctx.common_policy_options.policy_digest.buffer[i]);
            }
            tpm2_tool_output("\n");
        }

        // Additional operations when session if a trial policy session
        if (pctx.common_policy_options.policy_session_type == TPM2_SE_TRIAL) {
            //save the policy buffer in a file for use later
            bool result = files_save_bytes_to_file(pctx.common_policy_options.policy_file,
                              (UINT8 *) &pctx.common_policy_options.policy_digest.buffer,
                                          pctx.common_policy_options.policy_digest.size);
            if (!result) {
                LOG_ERR("Failed to save policy digest into file \"%s\"",
                        pctx.common_policy_options.policy_file);
                return TPM2_RC_NO_RESULT;
            }
        }
    }

    if (pctx.common_policy_options.extend_policy_session) {
        tpm2_tool_output("EXTENDED_POLICY_SESSION_HANDLE: 0x%08X\n",
            pctx.common_policy_options.policy_session->sessionHandle );
    }

    return rval;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'f':
        pctx.common_policy_options.policy_file_flag = true;
        pctx.common_policy_options.policy_file = value;
        break;
    case 'F':
        pctx.pcr_policy_options.raw_pcrs_file = value;
        break;
    case 'g':
        pctx.common_policy_options.policy_digest_hash_alg
            = tpm2_alg_util_from_optarg(value);
        if(pctx.common_policy_options.policy_digest_hash_alg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'L':
        if (!pcr_parse_selections(value, &pctx.pcr_policy_options.pcr_selections)) {
            return false;
        }
        pctx.pcr_policy_options.is_set_list = true;
        break;
    case 'P':
        pctx.common_policy_options.policy_type.PolicyPCR = true;
        pctx.common_policy_options.policy_type.is_policy_type_selected= true;
        break;
    case 'a':
        pctx.common_policy_options.policy_session_type = TPM2_SE_POLICY;
        pctx.common_policy_options.extend_policy_session = true;
        break;
    case 'e':
        pctx.common_policy_options.extend_policy_session = true;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "policy-file",    required_argument,  NULL,   'f' },
        { "policy-digest-alg", required_argument, NULL, 'g'},
        { "set-list",       required_argument,  NULL,   'L' },
        { "pcr-input-file", required_argument,  NULL,   'F' },
        { "policy-pcr",     no_argument,        NULL,   'P' },
        { "auth-policy-session", no_argument, NULL,     'a'},
        { "extend-policy-session", no_argument, NULL,   'e'},
    };

    *opts = tpm2_options_new("f:g:L:F:Pae", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (pctx.common_policy_options.policy_file_flag == false &&
        pctx.common_policy_options.policy_session_type == TPM2_SE_TRIAL) {
        LOG_ERR("Provide the file name to store the resulting "
                "policy digest");
        return 1;
    }

    return parse_policy_type_specific_command(sapi_context) != TPM2_RC_SUCCESS;
}
