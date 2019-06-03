/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

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
    case 'o':
        ctx.policy_out_path = value;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
        break;
    case 'L': {
        bool result = pcr_parse_selections(value, &ctx.pcr_selection);
        if (!result) {
            LOG_ERR("Could not parse PCR selections");
            return false;
        }
    } break;
    case 'S':
        ctx.session_path = value;
    break;
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "out-policy-file",    required_argument,  NULL,   'o' },
        { "pcr-input-file",     required_argument,  NULL,   'F' },
        { "set-list",           required_argument,  NULL,   'L' },
        { "session",            required_argument,  NULL,   'S' },
    };

    *opts = tpm2_options_new("o:F:L:S:", ARRAY_LEN(topts), topts, on_option,
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

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false, &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }


    bool result = tpm2_policy_build_pcr(ectx, ctx.session,
            ctx.raw_pcrs_file,
            &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build pcr policy");
        return tool_rc_general_error;
    }

    result = tpm2_policy_get_digest(ectx, ctx.session,
            &ctx.policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        return tool_rc_general_error;
    }

    tpm2_tool_output("policy-digest: 0x");
    UINT16 i;
    for(i = 0; i < ctx.policy_digest->size; i++) {
        tpm2_tool_output("%02X", ctx.policy_digest->buffer[i]);
    }
    tpm2_tool_output("\n");

    if (ctx.policy_out_path) {
        result = files_save_bytes_to_file(ctx.policy_out_path,
                    (UINT8 *) &ctx.policy_digest->buffer,
                    ctx.policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    ctx.policy_out_path);
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    free(ctx.policy_digest);
    return tpm2_session_close(&ctx.session);
}
