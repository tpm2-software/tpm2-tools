/* SPDX-License-Identifier: BSD-3-Clause */
#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

typedef struct tpm_ecephemeral_ctx tpm_ecephemeral_ctx;
struct tpm_ecephemeral_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    char *basepoint_x_coordinate_data_path;
    char *basepoint_y_data_path;
    char *eccpoint_M_data_path;

    TPM2B_ECC_POINT P1;
    TPM2B_SENSITIVE_DATA s2;
    TPM2B_ECC_PARAMETER y2;

    /*
     * Outputs
     */
    char *eccpoint_K_data_path;
    TPM2B_ECC_POINT *K;
    char *eccpoint_L_data_path;
    TPM2B_ECC_POINT *L;
    char *eccpoint_E_data_path;
    TPM2B_ECC_POINT *E;
    char *commit_counter_path;
    uint16_t counter;

    /*
     * Parameter hashes
     */
    char *cp_hash_path;
    TPM2B_DIGEST *cphash;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
};

static tpm_ecephemeral_ctx ctx;

static tool_rc commit(ESYS_CONTEXT *ectx) {

    return tpm2_commit(ectx, &ctx.signing_key.object, &ctx.P1, &ctx.s2, &ctx.y2,
        &ctx.K, &ctx.L, &ctx.E, &ctx.counter, ctx.cphash);
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

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
    is_file_op_success = files_save_ecc_point(ctx.K, ctx.eccpoint_K_data_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the ECC point K");
        return tool_rc_general_error;
    }

    is_file_op_success = files_save_ecc_point(ctx.L, ctx.eccpoint_L_data_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the ECC point L");
        return tool_rc_general_error;
    }

    is_file_op_success = files_save_ecc_point(ctx.E, ctx.eccpoint_E_data_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the ECC point E");
        return tool_rc_general_error;
    }

    FILE *fp = fopen(ctx.commit_counter_path, "wb");
    is_file_op_success = files_write_16(fp, ctx.counter);
    fclose(fp);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the ECC commit count");
        return tool_rc_general_error;
    }

    return tool_rc_success;
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
            ctx.signing_key.auth_str, &ctx.signing_key.object, false,
            TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    bool result = true;
    if (ctx.basepoint_x_coordinate_data_path) {
        result = files_load_ecc_point(ctx.eccpoint_M_data_path, &ctx.P1);
    }
    if (!result) {
        LOG_ERR("Failed to load input ECC point P1");
        return tool_rc_general_error;
    }

    if (ctx.basepoint_y_data_path) {
        result = files_load_ecc_parameter(ctx.basepoint_y_data_path, &ctx.y2);
    }
    if (!result) {
        LOG_ERR("Failed to load input ECC parameter y2");
        return tool_rc_general_error;
    }

    /*
     * 4. Configuration for calculating the pHash
     */
    ctx.cphash = ctx.cp_hash_path ? &ctx.cp_hash : 0;

    /*
     * 4.a Determine pHash length and alg
     */

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(void) {

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Specify a signing key");
        return tool_rc_option_error;
    }

    if (ctx.basepoint_y_data_path && !ctx.basepoint_x_coordinate_data_path) {
        LOG_ERR("Specify parameter data for basepoint X coordinate derivation");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify single argument with file input containing the "
                "octet array used to derive x-coordinate of a base point");
        return false;
    }

    ctx.basepoint_x_coordinate_data_path = strcmp("-", argv[0]) ? argv[0] : 0;

    return files_load_bytes_from_buffer_or_file_or_stdin(0,
        ctx.basepoint_x_coordinate_data_path, &ctx.s2.size, ctx.s2.buffer);
}

static bool on_option(char key, char *value) {

    switch (key) {
        case 'p':
            ctx.signing_key.auth_str = value;
            break;
        case 'c':
            ctx.signing_key.ctx_path = value;
            break;
        case 0:
            ctx.basepoint_y_data_path = value;
            break;
        case 1:
            ctx.eccpoint_M_data_path = value;
            break;
        case 2:
            ctx.eccpoint_K_data_path = value;
            break;
        case 3:
            ctx.eccpoint_L_data_path = value;
            break;
        case 'u':
            ctx.eccpoint_E_data_path = value;
            break;
        case 't':
            ctx.commit_counter_path = value;
            break;
        case 4:
            ctx.cp_hash_path = value;
            break;
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "auth",        required_argument, 0, 'p' },
      { "context",     required_argument, 0, 'c' },
      { "basepoint-y", required_argument, 0,  0  },
      { "eccpoint-P",  required_argument, 0,  1  },
      { "eccpoint-K",  required_argument, 0,  2  },
      { "eccpoint-L",  required_argument, 0,  3  },
      { "public",      required_argument, 0, 'u' },
      { "counter",     required_argument, 0, 't' },
      { "cphash",      required_argument, 0,  4  },
    };

    *opts = tpm2_options_new("p:c:t:u:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

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
    rc = commit(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("commit", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
