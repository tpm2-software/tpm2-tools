/* SPDX-License-Identifier: BSD-3-Clause */
#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
typedef struct tpm_ecdhzgen_ctx tpm_ecdhzgen_ctx;
struct tpm_ecdhzgen_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } ecc_key;

    TPM2B_ECC_POINT Q;
    const char *ecdh_pub_path;
    const char *ecdh_pub_key_path;

    /*
     * Outputs
     */
    const char *ecdh_Z_path;
    TPM2B_ECC_POINT *Z;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

};

static tpm_ecdhzgen_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR
};

static tool_rc ecdhzgen(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_ecdhzgen(ectx, &ctx.ecc_key.object, &ctx.Z,
        &ctx.Q, &ctx.cp_hash, ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed TPM2_CC_ECDH_ZGen");
    }

    return rc;
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
    is_file_op_success = files_save_ecc_point(ctx.Z, ctx.ecdh_Z_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the public");
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
    tool_rc  rc = tpm2_util_object_load_auth(ectx, ctx.ecc_key.ctx_path,
        ctx.ecc_key.auth_str, &ctx.ecc_key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to load object/ auth");
        return rc;
    }
    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    if (ctx.ecdh_pub_key_path) {
        TPM2B_PUBLIC public = { 0 };
        bool is_file_op_success = true;
        is_file_op_success = files_load_public(ctx.ecdh_pub_key_path, &public);
        if (!is_file_op_success) {
            LOG_ERR("Failed to load public input ECC public key");
            return tool_rc_general_error;
        }
        if (public.publicArea.type != TPM2_ALG_ECC) {
            LOG_ERR("Only ECC public keys can be used.");
            return tool_rc_general_error;
        }
        ctx.Q.point = public.publicArea.unique.ecc;
        ctx.Q.size = 0;
    } else {
        bool is_file_op_success = true;
        is_file_op_success = files_load_ecc_point(ctx.ecdh_pub_path, &ctx.Q);
        if (!is_file_op_success) {
            LOG_ERR("Failed to load public input ECC point Q");
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
        0,
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

    if (!ctx.ecc_key.ctx_path) {
        LOG_ERR("Specify an ecc public key handle for context");
        return tool_rc_option_error;
    }

    if (!ctx.ecdh_Z_path) {
        LOG_ERR("Specify path to save the ecdh secret or Z point");
        return tool_rc_option_error;
    }
    if (ctx.ecdh_pub_path && ctx.ecdh_pub_key_path) {
        LOG_ERR("Only pub key or pub point can be specified not both.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {

        case 'c':
            ctx.ecc_key.ctx_path = value;
            break;
        case 'p':
            ctx.ecc_key.auth_str = value;
            break;
        case 'u':
            ctx.ecdh_pub_path = value;
            break;
        case 'k':
            ctx.ecdh_pub_key_path = value;
            break;
        case 'o':
            ctx.ecdh_Z_path = value;
            break;
        case 0:
            ctx.cp_hash_path = value;
        break;
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "key-context", required_argument, 0, 'c' },
      { "key-auth",    required_argument, 0, 'p' },
      { "public",      required_argument, 0, 'u' },
      { "public-key",  required_argument, 0, 'k' },
      { "output",      required_argument, 0, 'o' },
      { "cphash",      required_argument, 0,  0  },

    };

    *opts = tpm2_options_new("c:p:u:k:o:", ARRAY_LEN(topts), topts,
            on_option, 0, 0);

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
    rc = ecdhzgen(ectx);
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
TPM2_TOOL_REGISTER("ecdhzgen", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
