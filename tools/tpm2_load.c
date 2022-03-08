/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_load_ctx tpm_load_ctx;
struct tpm_load_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        const char *pubpath;
        TPM2B_PUBLIC public;
        const char *privpath;
        TPM2B_PRIVATE private;
        ESYS_TR handle;
    } object;

    /*
     * Outputs
     */
    const char *namepath;
    const char *contextpath;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_load_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc load(ESYS_CONTEXT *ectx) {

    return tpm2_load(ectx, &ctx.parent.object, &ctx.object.private,
        &ctx.object.public, &ctx.object.handle, &ctx.cp_hash,
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
    TPM2B_NAME *name;
    rc = tpm2_tr_get_name(ectx, ctx.object.handle, &name);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.namepath) {
        bool result = files_save_bytes_to_file(ctx.namepath, name->name,
                name->size);
        free(name);
        if (!result) {
            return tool_rc_general_error;
        }
    } else {
        tpm2_tool_output("name: ");
        tpm2_util_print_tpm2b(name);
        tpm2_tool_output("\n");
        free(name);
    }

    return files_save_tpm_context_to_path(ectx, ctx.object.handle,
            ctx.contextpath);
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    bool is_file_op_success = files_load_public(ctx.object.pubpath,
        &ctx.object.public);
    if (!is_file_op_success) {
        return tool_rc_general_error;
    }

    is_file_op_success = files_load_private(ctx.object.privpath,
        &ctx.object.private);
    if (!is_file_op_success) {
        return tool_rc_general_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.parent.object.session,
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

    return tool_rc_success;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    tool_rc rc = tool_rc_success;
    if (!ctx.parent.ctx_path) {
        LOG_ERR("Expected parent object via -C");
        rc = tool_rc_option_error;
    }

    if (!ctx.object.pubpath) {
        LOG_ERR("Expected public object portion via -u");
        rc = tool_rc_option_error;
    }

    if (!ctx.object.privpath) {
        LOG_ERR("Expected private object portion via -r");
        rc = tool_rc_option_error;
    }

    if (!ctx.contextpath && !ctx.cp_hash_path) {
        LOG_ERR("Expected option -c");
        rc = tool_rc_option_error;
    }

    if (ctx.contextpath && ctx.cp_hash_path) {
        LOG_ERR("Cannot output contextpath when calculating cp_hash");
        rc = tool_rc_option_error;
    }

    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'u':
        ctx.object.pubpath = value;
        break;
    case 'r':
        ctx.object.privpath = value;
        break;
    case 'n':
        ctx.namepath = value;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'c':
        ctx.contextpath = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth",           required_argument, 0, 'P' },
      { "public",         required_argument, 0, 'u' },
      { "private",        required_argument, 0, 'r' },
      { "name",           required_argument, 0, 'n' },
      { "key-context",    required_argument, 0, 'c' },
      { "parent-context", required_argument, 0, 'C' },
      { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("P:u:r:n:C:c:", ARRAY_LEN(topts), topts, on_option,
        0, 0);

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
    rc = load(ectx);
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
    tool_rc rc = tpm2_session_close(&ctx.parent.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("load", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
