/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_capability.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    struct {
        char *ctx_path;
        tpm2_loaded_object object;
    } to_persist_key;

    TPMI_DH_PERSISTENT persist_handle;
    bool is_persistent_handle_specified;

    /*
     * Outputs
     */
    const char *output_arg;
    ESYS_TR out_tr;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_evictcontrol_ctx ctx = {
    .auth_hierarchy.ctx_path="o",
    .out_tr = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc evictcontrol(ESYS_CONTEXT *ectx) {

    /*
     * ESAPI is smart enough that if the object is persistent, to ignore the
     * argument for persistent handle. Thus we can use ESYS_TR output to
     * determine if it's evicted or not.
     */
    return tpm2_evictcontrol(ectx, &ctx.auth_hierarchy.object,
        &ctx.to_persist_key.object, ctx.persist_handle, &ctx.out_tr,
        &ctx.cp_hash, ctx.parameter_hash_algorithm);
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

    /*
     * Only Close a TR object if it's still resident in the TPM.
     * When these handles match, evictcontrol flushed it from the TPM.
     * It's evicted when ESAPI sends back a none handle on evictcontrol.
     *
     * XXX: This output is wrong because we can't determine what handle was
     * evicted on ESYS_TR input.
     *
     * See bug: https://github.com/tpm2-software/tpm2-tools/issues/1816
     */
    tpm2_tool_output("persistent-handle: 0x%x\n", ctx.persist_handle);

    bool is_evicted = (ctx.out_tr == ESYS_TR_NONE);
    tpm2_tool_output("action: %s\n", is_evicted ? "evicted" : "persisted");

    tool_rc tmp_rc = tool_rc_success;
    if (ctx.output_arg) {
        tmp_rc = files_save_ESYS_TR(ectx, ctx.out_tr, ctx.output_arg);
    }

    if (!is_evicted) {
        rc = tpm2_close(ectx, &ctx.out_tr);
    }

    return (tmp_rc == tool_rc_success) ? rc : tmp_rc;
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

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Object #2 */
    rc = tpm2_util_object_load(ectx, ctx.to_persist_key.ctx_path,
        &ctx.to_persist_key.object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    if (ctx.to_persist_key.object.handle >> TPM2_HR_SHIFT
            == TPM2_HT_PERSISTENT) {
        ctx.persist_handle = ctx.to_persist_key.object.handle;
        ctx.is_persistent_handle_specified = true;
    }

    /* If we've been given a handle or context object to persist and not an
     * explicit persistent handle to use, find an available vacant handle in
     * the persistent namespace and use that.
     *
     * XXX: We need away to figure out of object is persistent and skip it.
     */
    if (ctx.to_persist_key.ctx_path && !ctx.is_persistent_handle_specified) {
        bool is_platform = ctx.auth_hierarchy.object.handle == TPM2_RH_PLATFORM;
        rc = tpm2_capability_find_vacant_persistent_handle(ectx,
                is_platform, &ctx.persist_handle);
        if (rc != tool_rc_success) {
            return rc;
        }
        /* we searched and found a persistent handle, so mark that peristent handle valid */
        ctx.is_persistent_handle_specified = true;
    }

    if (ctx.output_arg && !ctx.is_persistent_handle_specified) {
        LOG_ERR("Cannot specify -o without using a persistent handle");
        return tool_rc_option_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
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

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (!ctx.to_persist_key.ctx_path) {
        LOG_ERR("Must specify the key object to be evicted.");
        return tool_rc_option_error;
    }

    if (!ctx.auth_hierarchy.ctx_path) {
        LOG_ERR("Must specify the auth hierarchy");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'c':
        ctx.to_persist_key.ctx_path = value;
        break;
    case 'o':
        ctx.output_arg = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc > 1) {
        LOG_ERR("Expected at most one persistent handle, got %d", argc);
        return false;
    }

    const char *value = argv[0];

    bool result = tpm2_util_string_to_uint32(value, &ctx.persist_handle);
    if (!result) {
        LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
            value);
        return false;
    }
    ctx.is_persistent_handle_specified = true;

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",      required_argument, 0, 'C' },
      { "auth",           required_argument, 0, 'P' },
      { "object-context", required_argument, 0, 'c' },
      { "output",         required_argument, 0, 'o' },
      { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("C:P:c:o:", ARRAY_LEN(topts), topts, on_option,
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
    rc = evictcontrol(ectx);
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
    tool_rc rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("evictcontrol", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
