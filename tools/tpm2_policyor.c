/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_policyor_ctx tpm2_policyor_ctx;
struct tpm2_policyor_ctx {
   //File path for the session context data
   const char *session_path;
   //List of policy digests that will be compounded
   TPML_DIGEST policy_list;
   //File path for storing the policy digest output
   const char *out_policy_dgst_path;
};

static tpm2_policyor_ctx ctx;

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'o':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'L':
        result = tpm2_policy_parse_policy_list(value, &ctx.policy_list);
        if (!result) {
            return false;
        }
        break;
    }

    return result;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "out-policy-file",        required_argument, NULL, 'o' },
        { "session",                required_argument, NULL, 'S' },
        { "policy-list",            required_argument, NULL, 'L' },
    };

    *opts = tpm2_options_new("o:S:L:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.out_policy_dgst_path) {
        LOG_ERR("Must specify -o output policy digest file.");
        return false;
    }

    //Minimum two policies needed to be specified for compounding
    if (ctx.policy_list.count < 1) {
        LOG_ERR("Must specify at least 2 policy digests for compounding.");
        return false;
    }

    return true;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPM2B_DIGEST *policy_digest = NULL;

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }


    tool_rc rc = tool_rc_general_error;

    tpm2_session *s = tpm2_session_restore(ectx, ctx.session_path, false);
    if (!s) {
        return rc;
    }

    /* Policy digest hash alg should match that of the session */
    if (ctx.policy_list.digests[0].size !=
        tpm2_alg_util_get_hash_size(tpm2_session_get_authhash(s))) {
        LOG_ERR("Policy digest hash alg should match that of the session.");
        return rc;
    }

    bool result = tpm2_policy_build_policyor(ectx, s, ctx.policy_list);
    if (!result) {
        LOG_ERR("Could not build policyor TPM");
        goto out;
    }

    result = tpm2_policy_get_digest(ectx, s, &policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        goto out;
    }

    tpm2_util_hexdump(policy_digest->buffer, policy_digest->size);
    tpm2_tool_output("\n");

    if (ctx.out_policy_dgst_path) {
        result = files_save_bytes_to_file(ctx.out_policy_dgst_path,
                    policy_digest->buffer, policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    ctx.out_policy_dgst_path);
            goto out;
        }
    }

    rc = tool_rc_success;

out:
    result = tpm2_session_close(&s);
    if (!result) {
        rc = tool_rc_general_error;
    }

    free(policy_digest);

    return rc;
}
