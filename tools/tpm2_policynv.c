/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"

#define MAX_SESSIONS 3
typedef struct tpm_policynv_ctx tpm_policynv_ctx;
struct tpm_policynv_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;

    TPM2B_OPERAND operand_b;
    UINT16 offset;
    TPM2_EO operation;

    const char *session_path;
    tpm2_session *session;

    /*
     * Outputs
     */
    const char *policy_digest_path;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_policynv_ctx ctx = {
    .operand_b = { .size = BUFFER_SIZE(TPM2B_OPERAND, buffer) },
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc policynv(ESYS_CONTEXT *ectx) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(ctx.session);
    return tpm2_policy_nv(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
        policy_session_handle, &ctx.operand_b, ctx.offset, ctx.operation,
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
    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_path);
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
        ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
        TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
        return rc;
    }

    rc = tpm2_session_restore(ectx, ctx.session_path, false, &ctx.session);
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
     * Ensure that NV index is large enough to compare the size of input data.
     */
    TPM2B_NV_PUBLIC *nv_public = 0;
    rc = tpm2_util_nv_read_public(ectx, ctx.nv_index, 0, &nv_public, 0, 0, 0,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to access NVRAM public area at index 0x%X",
                ctx.nv_index);
        free(nv_public);
        return rc;
    }

    if (ctx.operand_b.size > nv_public->nvPublic.dataSize - ctx.offset) {
        LOG_ERR("The operand size is larger than NV data"
                " starting at the offset");
        free(nv_public);
        return tool_rc_general_error;
    }
    free(nv_public);

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
        ctx.session,
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

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && ctx.policy_digest_path) {
        LOG_WARN("Cannot output policyhash when calculating cphash.");
        return tool_rc_option_error;
    }

    if (!ctx.operand_b.size) {
        LOG_WARN("Data to compare is of size 0");
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    switch (argc) {
    case 2:
        break;
    default:
        goto on_arg_error;
    }

    uint8_t argv_index_ctr = argc;
    do {
        argv_index_ctr--;
        if (!strcmp(argv[argv_index_ctr], "eq")) {
            ctx.operation = TPM2_EO_EQ;
        } else if (!strcmp(argv[argv_index_ctr], "neq")) {
            ctx.operation = TPM2_EO_NEQ;
        } else if (!strcmp(argv[argv_index_ctr], "sgt")) {
            ctx.operation = TPM2_EO_SIGNED_GT;
        } else if (!strcmp(argv[argv_index_ctr], "ugt")) {
            ctx.operation = TPM2_EO_UNSIGNED_GT;
        } else if (!strcmp(argv[argv_index_ctr], "slt")) {
            ctx.operation = TPM2_EO_SIGNED_LT;
        } else if (!strcmp(argv[argv_index_ctr], "ult")) {
            ctx.operation = TPM2_EO_UNSIGNED_LT;
        } else if (!strcmp(argv[argv_index_ctr], "sge")) {
            ctx.operation = TPM2_EO_SIGNED_GE;
        } else if (!strcmp(argv[argv_index_ctr], "uge")) {
            ctx.operation = TPM2_EO_UNSIGNED_GE;
        } else if (!strcmp(argv[argv_index_ctr], "sle")) {
            ctx.operation = TPM2_EO_SIGNED_LE;
        } else if (!strcmp(argv[argv_index_ctr], "ule")) {
            ctx.operation = TPM2_EO_UNSIGNED_LE;
        } else if (!strcmp(argv[argv_index_ctr], "bs")) {
            ctx.operation = TPM2_EO_BITSET;
        } else if (!strcmp(argv[argv_index_ctr], "bc")) {
            ctx.operation = TPM2_EO_BITCLEAR;
        } else {
            // Process it as NV index instead
            /*
             * Use the index as an authorization hierarchy If the user doesn't specify
             */
            if (!ctx.auth_hierarchy.ctx_path) {
                ctx.auth_hierarchy.ctx_path = argv[argv_index_ctr];
            }
            return on_arg_nv_index( 1, argv, &ctx.nv_index); //Only 1 arg for NV index
        }
    } while(argv_index_ctr > 0); // Loop to iterate through the two arguments
    /*
     * Invalid argument specified
     */
on_arg_error:
    LOG_ERR("Specify 2 arguments - NV-Index and Comparison-Operartion");
    return false;
}

static bool on_option(char key, char *value) {

    bool result = false;
    char *input_file;

    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'L':
        ctx.policy_digest_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'i':
        input_file = strcmp("-", value) ? value : 0;
        if (input_file) {
            result = files_get_file_size_path(value,
                    (long unsigned *) &ctx.operand_b.size);
        }
        if (input_file && !result) {
            return false;
        }
        result = files_load_bytes_from_buffer_or_file_or_stdin(0, input_file,
                &ctx.operand_b.size,
                ctx.operand_b.buffer);
        if (!result) {
            return false;
        }
        break;
    case 0:
        if (!tpm2_util_string_to_uint16(value, &ctx.offset)) {
            LOG_ERR("Could not convert starting offset, got: \"%s\"", value);
            return false;
        }
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    default:
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, 0, 'C' },
        { "auth",      required_argument, 0, 'P' },
        { "policy",    required_argument, 0, 'L' },
        { "session",   required_argument, 0, 'S' },
        { "input",     required_argument, 0, 'i' },
        { "offset",    required_argument, 0,  0  },
        { "cphash",    required_argument, 0,  1  },
    };

    *opts = tpm2_options_new("C:P:L:S:i:", ARRAY_LEN(topts), topts, on_option,
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
    rc = policynv(ectx);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policynv", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
