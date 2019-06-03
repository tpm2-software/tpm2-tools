/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_policysecret_ctx tpm2_policysecret_ctx;
struct tpm2_policysecret_ctx {
    //File path for the session context data
    const char *session_path;
    //File path for storing the policy digest output
    const char *out_policy_dgst_path;
    //Specifying the TPM object handle-id or the file path of context blob
    const char *context_arg;
    tpm2_loaded_object context_object;
    //Auth value of the auth object
    char *auth_str;
    TPM2B_DIGEST *policy_digest;
    tpm2_session *session;
    struct {
        UINT8 c : 1;
    } flags;
};

static tpm2_policysecret_ctx ctx;

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'o':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'c':
        ctx.context_arg = value;
        ctx.flags.c = 1;
        break;
    }

    return result;
}

bool on_arg (int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify a single auth value");
        return false;
    }

    if (!argc) {
        //empty auth
        return true;
    }

    ctx.auth_str = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "out-policy-file", required_argument, NULL, 'o' },
        { "session",     required_argument, NULL, 'S' },
        { "context",     required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("o:S:c:", ARRAY_LEN(topts), topts, on_option,
                             on_arg, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.flags.c) {
        LOG_ERR("Must specify -c handle-id/ context file path.");
        return false;
    }

    return true;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = is_input_option_args_valid();
    if (!result) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false, &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_util_object_load(ectx, ctx.context_arg,
                                &ctx.context_object);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_session *pwd_session;
    result = tpm2_auth_util_from_optarg(NULL, ctx.auth_str,
        &pwd_session, true);
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * Build a policysecret using the pwd session. If the event of
     * a failure:
     * 1. always close the pwd session.
     * 2. log the policy secret failure and return tool_rc_general_error.
     * 3. if the error was closing the policy secret session, return that rc.
     */
    result = tpm2_policy_build_policysecret(ectx, ctx.session,
        pwd_session, ctx.context_object.tr_handle);
    rc = tpm2_session_close(&pwd_session);
    if (!result) {
        LOG_ERR("Could not build policysecret");
        return tool_rc_general_error;
    }

    if (rc != tool_rc_success) {
        return rc;
    }

    result = tpm2_policy_get_digest(ectx, ctx.session, &ctx.policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        return tool_rc_general_error;
    }

    tpm2_util_hexdump(ctx.policy_digest->buffer, ctx.policy_digest->size);
    tpm2_tool_output("\n");

    if(ctx.out_policy_dgst_path) {
        result = files_save_bytes_to_file(ctx.out_policy_dgst_path,
                    ctx.policy_digest->buffer, ctx.policy_digest->size);
        if (!result) {
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
