/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policypcr_ctx tpm2_policypcr_ctx;
struct tpm2_policypcr_ctx {
    const char *session_path;
    const char *raw_pcrs_file;
    TPML_PCR_SELECTION pcr_selection;
    const char *policy_out_path;
    TPM2B_DIGEST *policy_digest;
    tpm2_session *session;
};

static tpm2_policypcr_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'L':
        ctx.policy_out_path = value;
        break;
    case 'f':
        ctx.raw_pcrs_file = value;
        break;
    case 'l': {
        bool result = pcr_parse_selections(value, &ctx.pcr_selection);
        if (!result) {
            LOG_ERR("Could not parse PCR selections");
            return false;
        }
    }
        break;
    case 'S':
        ctx.session_path = value;
        break;
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",   required_argument,  NULL, 'L' },
        { "pcr",      required_argument,  NULL, 'f' },
        { "pcr-list", required_argument,  NULL, 'l' },
        { "session",  required_argument,  NULL, 'S' },
    };

    *opts = tpm2_options_new("L:f:l:S:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool option_fail = false;
    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        option_fail = true;
    }

    if (!ctx.pcr_selection.count) {
        LOG_ERR("Must specify -L pcr selection list.");
        option_fail = true;
    }

    if (option_fail) {
        return tool_rc_general_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_pcr(ectx, ctx.session, ctx.raw_pcrs_file,
            &ctx.pcr_selection);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build pcr policy");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_out_path);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    free(ctx.policy_digest);
    return tpm2_session_close(&ctx.session);
}
