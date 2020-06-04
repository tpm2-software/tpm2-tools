/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policysecret_ctx tpm2_policysecret_ctx;
struct tpm2_policysecret_ctx {
    struct {
        const char *ctx_path; //auth_entity.ctx_path
        const char *auth_str; //auth_str
        tpm2_loaded_object object; //context_object && pwd_session
    } auth_entity;

    //File path for storing the policy digest output
    const char *policy_digest_path;
    //File path for the session context data
    const char *extended_session_path;
    tpm2_session *extended_session;

    INT32 expiration;

    char *policy_ticket_path;

    char *policy_timeout_path;

    const char *qualifier_data_arg;

    bool is_nonce_tpm;

    struct {
        UINT8 c :1;
    } flags;

    char *cp_hash_path;
};

static tpm2_policysecret_ctx ctx;

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'L':
        ctx.policy_digest_path = value;
        break;
    case 'S':
        ctx.extended_session_path = value;
        break;
    case 'c':
        ctx.auth_entity.ctx_path = value;
        ctx.flags.c = 1;
        break;
    case 0:
        ctx.policy_ticket_path = value;
        break;
    case 1:
        ctx.policy_timeout_path = value;
        break;
    case 't':
        result = tpm2_util_string_to_int32(value, &ctx.expiration);
        if (!result) {
            LOG_ERR("Failed reading expiration duration from value, got:\"%s\"",
                    value);
            return false;
        }
        break;
    case 'x':
        ctx.is_nonce_tpm = true;
        break;
    case 'q':
        ctx.qualifier_data_arg = value;
        break;
    case 2:
        ctx.cp_hash_path = value;
        break;
    }

    return result;
}

static bool on_arg(int argc, char **argv) {

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

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",         required_argument, NULL, 'L' },
        { "session",        required_argument, NULL, 'S' },
        { "object-context", required_argument, NULL, 'c' },
        { "expiration",     required_argument, NULL, 't' },
        { "nonce-tpm",      no_argument,       NULL, 'x' },
        { "ticket",         required_argument, NULL,  0  },
        { "timeout",        required_argument, NULL,  1  },
        { "qualification",  required_argument, NULL, 'q' },
        { "cphash",         required_argument, NULL,  2  },
    };

    *opts = tpm2_options_new("L:S:c:t:q:x", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.extended_session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.flags.c) {
        LOG_ERR("Must specify -c handle-id/ context file path.");
        return false;
    }

    if (ctx.cp_hash_path && ctx.policy_digest_path) {
        LOG_WARN("Cannot output policyhash when calculating cphash.");
        return false;
    }

    return true;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = is_input_option_args_valid();
    if (!result) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.extended_session_path, false,
            &ctx.extended_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * The auth string of the referenced object is strictly for a password session
     */
    rc = tpm2_util_object_load_auth(ectx, ctx.auth_entity.ctx_path,
            ctx.auth_entity.auth_str, &ctx.auth_entity.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (!ctx.cp_hash_path) {
        /*
         * Build a policysecret using the pwd session. If the event of
         * a failure:
         * 1. always close the pwd session.
         * 2. log the policy secret failure and return tool_rc_general_error.
         * 3. if the error was closing the policy secret session, return that rc.
         */
        TPMT_TK_AUTH *policy_ticket = NULL;
        TPM2B_TIMEOUT *timeout = NULL;
        rc = tpm2_policy_build_policysecret(ectx, ctx.extended_session,
                &ctx.auth_entity.object, ctx.expiration, &policy_ticket, &timeout,
                ctx.is_nonce_tpm, ctx.qualifier_data_arg, NULL);
        tool_rc rc2 = tpm2_session_close(&ctx.auth_entity.object.session);
        if (rc != tool_rc_success) {
            goto tpm2_tool_onrun_out;
        }
        if (rc2 != tool_rc_success) {
            rc = rc2;
            goto tpm2_tool_onrun_out;
        }

        rc = tpm2_policy_tool_finish(ectx, ctx.extended_session,
                ctx.policy_digest_path);
        if (rc != tool_rc_success) {
            goto tpm2_tool_onrun_out;
        }

        if (ctx.policy_timeout_path) {
            if(!timeout->size) {
                LOG_WARN("Policy assertion did not produce timeout");
            } else {
                result = files_save_bytes_to_file(ctx.policy_timeout_path,
                timeout->buffer, timeout->size);
            }
        }
        if (!result) {
            LOG_ERR("Failed to save timeout to file.");
            rc = tool_rc_general_error;
            goto tpm2_tool_onrun_out;
        }

        if (ctx.policy_ticket_path) {
            if (!policy_ticket->digest.size) {
                LOG_WARN("Policy assertion did not produce auth ticket.");
            } else {
                result = files_save_authorization_ticket(policy_ticket,
                ctx.policy_ticket_path);
            }
        }
        if (!result) {
            LOG_ERR("Failed to save auth ticket");
            rc = tool_rc_general_error;
        }

tpm2_tool_onrun_out:
        free(policy_ticket);
        free(timeout);
        if (rc != tool_rc_success) {
            LOG_ERR("Could not build policysecret");
        }
        return rc;
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = tpm2_policy_build_policysecret(ectx, ctx.extended_session,
        &ctx.auth_entity.object, ctx.expiration, NULL, NULL, ctx.is_nonce_tpm,
        ctx.qualifier_data_arg, &cp_hash);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed cphash calculation operation");
        return rc;
    }

    result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        LOG_ERR("Failed saving command parameter hash for policysecret");
        rc = tool_rc_general_error;
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.extended_session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policysecret", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
