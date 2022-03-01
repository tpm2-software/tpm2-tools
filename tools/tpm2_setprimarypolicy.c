/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_setprimarypolicy_ctx tpm_setprimarypolicy_ctx;
struct tpm_setprimarypolicy_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } hierarchy;

    const char *policy_path;
    TPM2B_DIGEST *auth_policy;
    TPMI_ALG_HASH hash_algorithm;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_setprimarypolicy_ctx ctx = {
    .hash_algorithm = TPM2_ALG_NULL,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc setprimarypolicy(ESYS_CONTEXT *ectx) {

    return tpm2_setprimarypolicy(ectx, &ctx.hierarchy.object, ctx.auth_policy,
        ctx.hash_algorithm, &ctx.cp_hash, ctx.parameter_hash_algorithm);
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.hierarchy.ctx_path,
            ctx.hierarchy.auth_str, &ctx.hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O|TPM2_HANDLE_FLAGS_P|TPM2_HANDLE_FLAGS_E|
            TPM2_HANDLE_FLAGS_L);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    if (ctx.policy_path) {

        ctx.auth_policy = malloc(UINT16_MAX + sizeof(uint16_t));
        if (!ctx.auth_policy) {
            LOG_ERR("oom");
            return tool_rc_general_error;
        }

        (ctx.auth_policy)->size = UINT16_MAX;
        bool result = files_load_bytes_from_path(ctx.policy_path,
                (ctx.auth_policy)->buffer, &((ctx.auth_policy)->size));
        if (!result) {
            LOG_ERR("Failed loading policy digest from path");
            return tool_rc_general_error;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */


    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.hierarchy.object.session,
        0,
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

static tool_rc check_options(ESYS_CONTEXT * ectx) {

    UNUSED(ectx);

    if (!ctx.hierarchy.ctx_path) {
        LOG_ERR("Must specify the hierarchy '-C'.");
        return tool_rc_option_error;
    }

    tool_rc rc = tool_rc_success;
    if (ctx.policy_path) {
        unsigned long file_size = 0;
        bool result = files_get_file_size_path(ctx.policy_path, &file_size);
        if (!result || file_size == 0) {
            rc = tool_rc_general_error;
        }
    }

    return rc;
}

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'C':
        ctx.hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.hierarchy.auth_str = value;
        break;
    case 'L':
        ctx.policy_path = value;
        break;
    case 'g':
        ctx.hash_algorithm = tpm2_alg_util_from_optarg(value,
            tpm2_alg_util_flags_hash);
        if (ctx.hash_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert to number or lookup algorithm, got: "
                    "\"%s\"", value);
            return false;
        }
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "hierarchy",      required_argument, 0, 'C' },
        { "auth",           required_argument, 0, 'P' },
        { "policy",         required_argument, 0, 'L' },
        { "hash-algorithm", required_argument, 0, 'g' },
        { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("C:P:L:g:", ARRAY_LEN(topts), topts,
        on_option, 0, 0);

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
    rc = setprimarypolicy(ectx);
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
    free(ctx.auth_policy);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.hierarchy.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("setprimarypolicy", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
