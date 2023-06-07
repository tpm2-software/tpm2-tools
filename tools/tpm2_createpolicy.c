/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

//Records the type of policy and if one is selected
typedef struct {
    bool policy_pcr;
} policy_type;

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
typedef struct tpm2_pcr_policy_options tpm2_pcr_policy_options;
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

static tool_rc parse_policy_type_specific_command(ESYS_CONTEXT *ectx) {

    if (!pctx.common_policy_options.policy_type.policy_pcr) {
        LOG_ERR("Only PCR policy is currently supported!");
        return tool_rc_option_error;
    }

    tpm2_session_data *session_data =tpm2_session_data_new(
            pctx.common_policy_options.policy_session_type);
    if (!session_data) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    tpm2_session_set_authhash(session_data,
            pctx.common_policy_options.policy_digest_hash_alg);

    tpm2_session **s = &pctx.common_policy_options.policy_session;

    tool_rc rc = tpm2_session_open(ectx, session_data, s);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_pcr(ectx, pctx.common_policy_options.policy_session,
            pctx.pcr_policy_options.raw_pcrs_file,
            &pctx.pcr_policy_options.pcr_selections, NULL, NULL);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build pcr policy");
        return rc;
    }

    rc = tpm2_policy_get_digest(ectx, pctx.common_policy_options.policy_session,
        &pctx.common_policy_options.policy_digest, 0, TPM2_ALG_ERROR);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build tpm policy");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx,
            pctx.common_policy_options.policy_session,
            pctx.common_policy_options.policy_file);
}

static bool on_option(char key, char *value) {

    bool result = true;
    switch (key) {
    case 'L':
        pctx.common_policy_options.policy_file_flag = true;
        pctx.common_policy_options.policy_file = value;
        break;
    case 'f':
        pctx.pcr_policy_options.raw_pcrs_file = value;
        break;
    case 'g':
        pctx.common_policy_options.policy_digest_hash_alg =
                tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (pctx.common_policy_options.policy_digest_hash_alg
                == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'l':
        result = pcr_parse_selections(value,
            &pctx.pcr_policy_options.pcr_selections, NULL);
        if (!result) {
            LOG_ERR("Failed to parse PCR string %s", value);
            return false;
        }
        break;
    case 0:
        pctx.common_policy_options.policy_type.policy_pcr = true;
        break;
    case 1:
        pctx.common_policy_options.policy_session_type = TPM2_SE_POLICY;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "policy",              required_argument, NULL, 'L' },
        { "policy-algorithm",    required_argument, NULL, 'g' },
        { "pcr-list",            required_argument, NULL, 'l' },
        { "pcr",                 required_argument, NULL, 'f' },
        { "policy-pcr",          no_argument,       NULL,  0  },
        { "policy-session",      no_argument,       NULL,  1  },
    };

    *opts = tpm2_options_new("L:g:l:f:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (pctx.common_policy_options.policy_file_flag == false
            && pctx.common_policy_options.policy_session_type
                    == TPM2_SE_TRIAL) {
        LOG_ERR("Provide the file name to store the resulting "
                "policy digest");
        return tool_rc_option_error;
    }

    return parse_policy_type_specific_command(ectx);
}

static void tpm2_tool_onexit(void) {

    free(pctx.common_policy_options.policy_digest);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("createpolicy", tpm2_tool_onstart, tpm2_tool_onrun, NULL, tpm2_tool_onexit)
