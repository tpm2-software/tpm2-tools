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

typedef struct tpm2_policypassword_ctx tpm2_policypassword_ctx;
struct tpm2_policypassword_ctx {
   //File path for the session context data
   const char *session_path;
   //File path for storing the policy digest output
   const char *out_policy_dgst_path;
};

static tpm2_policypassword_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "out-policy-file",    required_argument, NULL, 'o' },
        { "session",            required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("o:S:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }
    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPM2B_DIGEST *policy_digest = NULL;
    bool retval = is_input_option_args_valid();
    if (!retval) {
        return -1;
    }

    int rc = 1;
    tpm2_session *s = tpm2_session_restore(ectx, ctx.session_path, false);
    if (!s) {
        return rc;
    }

    bool result = tpm2_policy_build_policypassword(ectx, s);
    if (!result) {
        LOG_ERR("Could not build policypassword TPM");
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

    rc = 0;

out:

    result = tpm2_session_close(&s);
    if (!result) {
        rc = 1;
    }

    free(policy_digest);

    return rc;
}
