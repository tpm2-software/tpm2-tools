/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policysecret_ctx tpm2_policysecret_ctx;
struct tpm2_policysecret_ctx {
    struct {
        const char *ctx_path;//auth_entity.ctx_path
        const char *auth_str;//auth_str
        tpm2_loaded_object object;//context_object && pwd_session
    } auth_entity;

    //File path for storing the policy digest output
    const char *out_policy_dgst_path;
    TPM2B_DIGEST *policy_digest;
    //File path for the session context data
    const char *extended_session_path;
    tpm2_session *extended_session;

    struct {
        UINT8 c : 1;
    } flags;
};

static tpm2_policysecret_ctx ctx;

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.extended_session_path = value;
        break;
    case 'c':
        ctx.auth_entity.ctx_path = value;
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

    ctx.auth_entity.auth_str = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",         required_argument, NULL, 'L' },
        { "session",        required_argument, NULL, 'S' },
        { "object-context", required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("L:S:c:", ARRAY_LEN(topts), topts, on_option,
                             on_arg, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.extended_session_path) {
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

    tool_rc rc = tpm2_session_restore(ectx, ctx.extended_session_path, false, &ctx.extended_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.auth_entity.ctx_path,
            ctx.auth_entity.auth_str, &ctx.auth_entity.object, true,
            TPM2_HANDLES_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * Build a policysecret using the pwd session. If the event of
     * a failure:
     * 1. always close the pwd session.
     * 2. log the policy secret failure and return tool_rc_general_error.
     * 3. if the error was closing the policy secret session, return that rc.
     */
    rc = tpm2_policy_build_policysecret(ectx, ctx.extended_session,
        &ctx.auth_entity.object);
    tool_rc rc2 = tpm2_session_close(&ctx.auth_entity.object.session);
    if (rc != tool_rc_success) {
        return rc;
    }
    if (rc2 != tool_rc_success) {
        return rc2;
    }

    rc = tpm2_session_close(&ctx.auth_entity.object.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policysecret");
        return rc;
    }

    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_get_digest(ectx, ctx.extended_session, &ctx.policy_digest);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build tpm policy");
        return rc;
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
    return tpm2_session_close(&ctx.extended_session);
}
