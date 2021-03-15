/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct changeeps_ctx changeeps_ctx;
#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2
struct changeeps_ctx {
    /*
     * Inputs
     */
    const char *auth_str;
    tpm2_session *auth_session;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static changeeps_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
};

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            LOG_ERR("Failed to save cpHash");
            return tool_rc_general_error;
        }
    }

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */
    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth_str,
        &ctx.auth_session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed loading platform auth.");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. Command specific initializations dependent on loaded objects
     */

    /*
     * 4. Configuration for calculating the pHash
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_session,
        ctx.aux_session[0],
        ctx.aux_session[1]
    };

    /*
     * 4.a Determine pHash length and alg
     */
    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    return tool_rc_success;
}

static tool_rc check_options(void) {

    if (ctx.cp_hash_path && !ctx.rp_hash_path) {
        LOG_WARN("EPS not changed. Only cpHash is calculated.");
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'p':
        ctx.auth_str = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "auth",   required_argument, NULL, 'p' },
        { "cphash", required_argument, NULL,  0  },
        { "rphash", required_argument, NULL,  1  },
        { "session",required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("p:S:", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
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
    rc = tpm2_changeeps(ectx, ctx.auth_session, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0],
        ctx.aux_session_handle[1]);
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

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }
    /*
     * 3. Close auxiliary sessions
     */
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("changeeps", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
