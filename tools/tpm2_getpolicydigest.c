/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_getpolicydigest_ctx tpm_getpolicydigest_ctx;
struct tpm_getpolicydigest_ctx {
    /*
     * Input options
     */
    bool hex;

    /*
     * Outputs
     */
    const char *output_file;
    TPM2B_DIGEST *policy_digest;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux Sessions
     */
    tpm2_session *session;
    const char *session_path;
    ESYS_TR session_handle;
};

static tpm_getpolicydigest_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc get_policydigest(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    tool_rc rc = tpm2_policy_getdigest(ectx, ctx.session_handle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &ctx.policy_digest,
        &ctx.cp_hash, ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed TPM2_CC_PolicyGetDigest");
    }

    return rc;
}

static tool_rc process_outputs(void) {

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
     * Either open an output file, or if stdout, do nothing as -Q
     * was specified.
     */
    FILE *out = stdout;
    if (ctx.output_file) {
        out = fopen(ctx.output_file, "wb+");
        if (!out) {
            LOG_ERR("Could not open output file \"%s\", error: %s",
                    ctx.output_file, strerror(errno));
            rc = tool_rc_general_error;
            goto out;
        }
    } else if (!output_enabled) {
        goto out;
    }

    if (ctx.hex) {
        tpm2_util_print_tpm2b2(out, ctx.policy_digest);
        goto out;
    }

    is_file_op_success = files_write_bytes(out, ctx.policy_digest->buffer,
        ctx.policy_digest->size);
    if (!is_file_op_success) {
        rc = tool_rc_general_error;
    }

out:
    if (out && out != stdout) {
        fclose(out);
    }

    return rc;
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
     * Note: Old-auth value is ignored when calculating cpHash.
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    tool_rc rc = tool_rc_success;
    TPM2_HANDLE handle;
    bool result = tpm2_util_string_to_uint32(ctx.session_path, &handle);
    if (result) {
        rc = tpm2_util_sys_handle_to_esys_handle(ectx, handle,
            &ctx.session_handle);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else {
        rc = tpm2_session_restore(ectx, ctx.session_path, false, &ctx.session);
        if (rc != tool_rc_success) {
            return rc;
        }
        ctx.session_handle = tpm2_session_get_handle(ctx.session);
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.session,
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

static tool_rc check_options(void) {

    if (!ctx.session_path) {
        LOG_ERR("Specify the session context.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    UNUSED(key);

    switch (key) {
    case 'o':
        ctx.output_file = value;
        break;
    case 0:
        ctx.hex = true;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "output",       required_argument, 0, 'o' },
        { "hex",          no_argument,       0,  0  },
        { "session",      required_argument, 0, 'S' },
        { "cphash",       required_argument, 0,  1  },
    };

    *opts = tpm2_options_new("S:o:", ARRAY_LEN(topts), topts, on_option, 0, 0);

    return *opts != 0;
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
    rc = get_policydigest(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs();
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    free(ctx.policy_digest);

    /*
     * 2. Close authorization sessions
     */
    return tpm2_session_close(&ctx.session);

    /*
     * 3. Close auxiliary sessions
     */
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("getpolicydigest", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
