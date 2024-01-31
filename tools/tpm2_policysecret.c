/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm2_policysecret_ctx tpm2_policysecret_ctx;
struct tpm2_policysecret_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_entity;

    INT32 expiration;
    const char *qualifier_data_arg;
    bool is_nonce_tpm;

    const char *extended_session_path;
    tpm2_session *extended_session;

    /*
     * Outputs
     */
    TPMT_TK_AUTH *policy_ticket;
    char *policy_ticket_path;
    TPM2B_TIMEOUT *timeout;
    char *policy_timeout_path;
    const char *policy_digest_path;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm2_policysecret_ctx ctx= {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc policysecret(ESYS_CONTEXT *ectx) {

    return tpm2_policy_build_policysecret(ectx, ctx.extended_session,
        &ctx.auth_entity.object, ctx.expiration, &ctx.policy_ticket,
        &ctx.timeout, ctx.is_nonce_tpm, ctx.qualifier_data_arg, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    rc = tpm2_policy_tool_finish(ectx, ctx.extended_session,
        ctx.policy_digest_path);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.policy_timeout_path) {
        if(!ctx.timeout->size) {
            LOG_WARN("Policy assertion did not produce timeout");
        } else {
            is_file_op_success = files_save_bytes_to_file(
                ctx.policy_timeout_path, ctx.timeout->buffer,
                ctx.timeout->size);

            if (!is_file_op_success) {
                LOG_ERR("Failed to save timeout to file.");
                return tool_rc_general_error;
            }
        }
    }

    if (ctx.policy_ticket_path) {
        if (!ctx.policy_ticket->digest.size) {
            LOG_WARN("Policy assertion did not produce auth ticket.");
        } else {
            is_file_op_success = files_save_authorization_ticket(
                ctx.policy_ticket, ctx.policy_ticket_path);

            if (!is_file_op_success) {
                LOG_ERR("Failed to save auth ticket");
                return tool_rc_general_error;
            }
        }
    }

    return rc;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * The auth string of the referenced object is strictly for
     * a password session
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_entity.ctx_path,
            ctx.auth_entity.auth_str, &ctx.auth_entity.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_session_restore(ectx, ctx.extended_session_path, false,
            &ctx.extended_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_entity.object.session,
        ctx.extended_session,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (!ctx.extended_session_path) {
        LOG_ERR("Must specify -S session file.");
        return tool_rc_option_error;
    }

    if (!ctx.auth_entity.ctx_path) {
        LOG_ERR("Must specify -c handle-id/ context file path.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && ctx.policy_digest_path) {
        LOG_ERR("Cannot output policyhash when calculating cphash.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

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
        { "policy",         required_argument, 0, 'L' },
        { "session",        required_argument, 0, 'S' },
        { "object-context", required_argument, 0, 'c' },
        { "expiration",     required_argument, 0, 't' },
        { "nonce-tpm",      no_argument,       0, 'x' },
        { "ticket",         required_argument, 0,  0  },
        { "timeout",        required_argument, 0,  1  },
        { "qualification",  required_argument, 0, 'q' },
        { "cphash",         required_argument, 0,  2  },
    };

    *opts = tpm2_options_new("L:S:c:t:q:x", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = policysecret(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    free(ctx.policy_ticket);
    free(ctx.timeout);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_entity.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.extended_session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policysecret", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
