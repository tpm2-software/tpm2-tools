/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_policyauthorize_ctx tpm2_policyauthorize_ctx;
struct tpm2_policyauthorize_ctx {
   //File path for the session context data
   const char *session_path;
   //File path for the policy digest that will be authorized
   const char *policy_digest_path;
   //File path for the policy qualifier data
   const char *qualifier_data_path;
   //File path for the verifying public key name
   const char *verifying_pubkey_path;
   //File path for the verification ticket
   const char *ticket_path;
   //File path for storing the policy digest output
   const char *out_policy_dgst_path;

   tpm2_session *session;
   TPM2B_DIGEST *policy_digest;
};

static tpm2_policyauthorize_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'i':
        ctx.policy_digest_path = value;
        break;
    case 'q':
        ctx.qualifier_data_path = value;
        break;
    case 'n':
        ctx.verifying_pubkey_path = value;
        break;
    case 't':
        ctx.ticket_path = value;
        break;
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "out-policy-file",    required_argument, NULL, 'o' },
        { "session",            required_argument, NULL, 'S' },
        { "in-policy-file",     required_argument, NULL, 'i' },
        { "qualify-data",       required_argument, NULL, 'q' },
        { "name",               required_argument, NULL, 'n' },
        { "ticket",             required_argument, NULL, 't' },
    };

    *opts = tpm2_options_new("o:S:i:q:n:t:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

bool is_check_input_options_ok(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.policy_digest_path) {
        LOG_ERR("Must specify -a p name.");
        return false;
    }

    if (!ctx.verifying_pubkey_path) {
        LOG_ERR("Must specify -c u name.");
        return false;
    }

    return true;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!is_check_input_options_ok()) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false, &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_policyauthorize(ectx, ctx.session,
                        ctx.policy_digest_path,
                        ctx.qualifier_data_path, ctx.verifying_pubkey_path, ctx.ticket_path);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build tpm authorized policy");
        return rc;
    }

    bool result = tpm2_policy_get_digest(ectx, ctx.session, &ctx.policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        return tool_rc_general_error;
    }

    tpm2_util_hexdump(ctx.policy_digest->buffer, ctx.policy_digest->size);
    tpm2_tool_output("\n");

    if (ctx.out_policy_dgst_path) {
        result = files_save_bytes_to_file(ctx.out_policy_dgst_path,
                    ctx.policy_digest->buffer, ctx.policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    ctx.out_policy_dgst_path);
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
