/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policylocality_ctx tpm2_policylocality_ctx;
struct tpm2_policylocality_ctx {
    const char *session_path;
    TPMA_LOCALITY locality;
    const char *out_policy_dgst_path;
    TPM2B_DIGEST *policy_digest;
    tpm2_session *session;
};

static tpm2_policylocality_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'S':
        ctx.session_path = value;
        break;
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    }
    return true;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify only the TPM2 locality.");
        return false;
    }

    if (!argc) {
        LOG_ERR("TPM2 locality must be specified.");
        return false;
    }

    if (strcmp(argv[0], "zero")) {
        ctx.locality = TPMA_LOCALITY_TPM2_LOC_ZERO;
    } else if (strcmp(argv[0], "one")) {
        ctx.locality = TPMA_LOCALITY_TPM2_LOC_ONE;
    } else if (strcmp(argv[0], "two")) {
        ctx.locality = TPMA_LOCALITY_TPM2_LOC_TWO;
    } else if (strcmp(argv[0], "three")) {
        ctx.locality = TPMA_LOCALITY_TPM2_LOC_THREE;
    } else if (strcmp(argv[0], "four")) {
        ctx.locality = TPMA_LOCALITY_TPM2_LOC_FOUR;
    } else {
        bool result = tpm2_util_string_to_uint8(argv[0], &ctx.locality);
        if (!result) {
            LOG_ERR("Could not convert locality to number, got: \"%s\"",
                    argv[0]);
            return false;
        }
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "session", required_argument,  NULL, 'S' },
        { "policy",  required_argument,  NULL, 'L' },
    };

    *opts = tpm2_options_new("S:L:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_policylocality(ectx, ctx.session, ctx.locality);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build TPM policy_locality");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.out_policy_dgst_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    free(ctx.policy_digest);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policylocality", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
