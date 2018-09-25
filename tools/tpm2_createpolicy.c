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
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

//Records the type of policy and if one is selected
typedef struct {
    bool PolicyPCR;
}policy_type;

//Common policy options
typedef struct tpm2_common_policy_options tpm2_common_policy_options;
struct tpm2_common_policy_options {
    tpm2_session *policy_session; // policy session
    TPM2_SE policy_session_type; // TPM2_SE_TRIAL or TPM2_SE_POLICY
    TPM2B_DIGEST *policy_digest; // buffer to hold policy digest
    TPMI_ALG_HASH policy_digest_hash_alg; // hash alg of final policy digest
    char *policy_file; // filepath for the policy digest
    bool policy_file_flag; // if policy file input has been given
    policy_type policy_type;
    const char *context_file;
};

//pcr policy options
typedef struct  tpm2_pcr_policy_options tpm2_pcr_policy_options;
struct tpm2_pcr_policy_options {
    char *raw_pcrs_file; // filepath of input raw pcrs file
    TPML_PCR_SELECTION pcr_selections; // records user pcr selection per setlist
};

typedef struct create_policy_ctx create_policy_ctx;
struct create_policy_ctx {
    tpm2_common_policy_options common_policy_options;
    tpm2_pcr_policy_options pcr_policy_options;
};

#define TPM2_COMMON_POLICY_INIT { \
            .policy_session = NULL, \
            .policy_session_type = TPM2_SE_TRIAL, \
            .policy_digest = NULL, \
            .policy_digest_hash_alg = TPM2_ALG_SHA256, \
        }

static create_policy_ctx pctx = {
    .common_policy_options = TPM2_COMMON_POLICY_INIT
};

static bool parse_policy_type_specific_command(ESYS_CONTEXT *ectx) {

    if (!pctx.common_policy_options.policy_type.PolicyPCR){
        LOG_ERR("Only PCR policy is currently supported!");
        return false;
    }

    tpm2_session_data *session_data =
            tpm2_session_data_new(pctx.common_policy_options.policy_session_type);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session_set_authhash(session_data,
            pctx.common_policy_options.policy_digest_hash_alg);

    pctx.common_policy_options.policy_session = tpm2_session_new(ectx,
            session_data);

    bool result = tpm2_policy_build_pcr(ectx, pctx.common_policy_options.policy_session,
            pctx.pcr_policy_options.raw_pcrs_file,
            &pctx.pcr_policy_options.pcr_selections);
    if (!result) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    result = tpm2_policy_get_digest(ectx,
            pctx.common_policy_options.policy_session,
            &pctx.common_policy_options.policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        return false;
    }

    // Display the policy digest during real policy session.
    if (pctx.common_policy_options.policy_session_type == TPM2_SE_POLICY) {
        tpm2_tool_output("policy-digest: 0x");
        int i;
        for(i = 0; i < pctx.common_policy_options.policy_digest->size; i++) {
            tpm2_tool_output("%02X", pctx.common_policy_options.policy_digest->buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    // Additional operations when session if a trial policy session
    if (pctx.common_policy_options.policy_session_type == TPM2_SE_TRIAL) {
        //save the policy buffer in a file for use later
        bool result = files_save_bytes_to_file(pctx.common_policy_options.policy_file,
                          (UINT8 *) &pctx.common_policy_options.policy_digest->buffer,
                                      pctx.common_policy_options.policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    pctx.common_policy_options.policy_file);
            return false;
        }
    }

    return true;
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
            = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if(pctx.common_policy_options.policy_digest_hash_alg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'L':
        if (!pcr_parse_selections(value, &pctx.pcr_policy_options.pcr_selections)) {
            return false;
        }
        break;
    case 'P':
        pctx.common_policy_options.policy_type.PolicyPCR = true;
        break;
    case 'a':
        pctx.common_policy_options.policy_session_type = TPM2_SE_POLICY;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "policy-file",         required_argument, NULL, 'f' },
        { "policy-digest-alg",   required_argument, NULL, 'g' },
        { "set-list",            required_argument, NULL, 'L' },
        { "pcr-input-file",      required_argument, NULL, 'F' },
        { "policy-pcr",          no_argument,       NULL, 'P' },
        { "auth-policy-session", no_argument,       NULL, 'a' },
    };

    *opts = tpm2_options_new("f:g:L:F:Pa", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (pctx.common_policy_options.policy_file_flag == false &&
        pctx.common_policy_options.policy_session_type == TPM2_SE_TRIAL) {
        LOG_ERR("Provide the file name to store the resulting "
                "policy digest");
        return 1;
    }

    bool result = parse_policy_type_specific_command(ectx);
    if (!result) {
        return 1;
    }

    return 0; 
}

void tpm2_onexit(void) {

    free(pctx.common_policy_options.policy_digest);
}
