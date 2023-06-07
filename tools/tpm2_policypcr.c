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
    struct tpm2_forwards forwards;
    const char *policy_out_path;
    TPM2B_DIGEST *raw_pcr_digest;
    tpm2_session *session;
};

static tpm2_policypcr_ctx ctx;

static bool on_arg(int argc, char **argv) {

    if ((ctx.raw_pcrs_file && argv[0]) || argc > 1) {
        LOG_ERR("Specify either pcr-digest or pcr data, not both");
        return false;
    }

    ctx.raw_pcr_digest = malloc(sizeof(TPM2B_DIGEST));
    if (!ctx.raw_pcr_digest) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }
    int q;
    ctx.raw_pcr_digest->size = BUFFER_SIZE(TPM2B_DIGEST, buffer);
    if ((q = tpm2_util_hex_to_byte_structure(argv[0], &ctx.raw_pcr_digest->size,
            ctx.raw_pcr_digest->buffer)) != 0) {
        free(ctx.raw_pcr_digest);
        LOG_ERR("FAILED: %d", q);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'L':
        ctx.policy_out_path = value;
        break;
    case 'f':
        ctx.raw_pcrs_file = value;
        break;
    case 'l': {
        bool result = pcr_parse_selections(value, &ctx.pcr_selection,
                                           &ctx.forwards);
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

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",   required_argument,  NULL, 'L' },
        { "pcr",      required_argument,  NULL, 'f' },
        { "pcr-list", required_argument,  NULL, 'l' },
        { "session",  required_argument,  NULL, 'S' },
    };

    *opts = tpm2_options_new("L:f:l:S:", ARRAY_LEN(topts), topts, on_option,
    on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool option_fail = false;
    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        option_fail = true;
    }

    if (!ctx.pcr_selection.count) {
        LOG_ERR("Must specify -l pcr selection list.");
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
            &ctx.pcr_selection, ctx.raw_pcr_digest, &ctx.forwards);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build pcr policy");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_out_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    free(ctx.raw_pcr_digest);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policypcr", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
