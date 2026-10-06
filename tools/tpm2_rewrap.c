/* SPDX-License-Identifier: BSD-3-Clause */

//**********************************************************************;
// Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
// Licensed under the Apache License 2.0 (the "License"). You may not use
// this file except in compliance with the License. You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0)
//
// See Victor Shoup, "OAEP reconsidered," Nov. 2000, <URL:
// http://www.shoup.net/papers/oaep.ps.Z> for problems with the security
// proof for the original OAEP scheme, which EME-OAEP is based on. A new
// proof can be found in E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern,
// "RSA-OEAP is Still Alive!", Dec. 2000, <URL:http://eprint.iacr.org/2000/061/>.
// The new proof has stronger requirements for the underlying permutation:
// "partial-one-wayness" instead of one-wayness. For the RSA function, this
// is an equivalent notion.
//**********************************************************************;
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_errata.h"
#include "tpm2_identity_util.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

#define TPM2_HANDLE_FLAGS_REWRAP \
    (TPM2_HANDLE_FLAGS_N|TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT)

#define MAX_SESSIONS 3
typedef struct tpm_rewrap_ctx tpm_rewrap_ctx;
struct tpm_rewrap_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        const char *ctx_path;
        tpm2_loaded_object object;
    } new_parent;

    char *input_key_file;
    TPM2B_PRIVATE in_duplicate;
    char *input_seed_file;
    TPM2B_ENCRYPTED_SECRET in_seed;
    char *public_key_file;
    TPM2B_PUBLIC public_key_data;
    TPM2B_NAME key_name;

    bool passin;

    /*
     * Outputs
     */
    char *output_key_file;
    TPM2B_PRIVATE *out_duplicate;
    char *output_seed_file;
    TPM2B_ENCRYPTED_SECRET *out_seed;
    bool autoflush;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_rewrap_ctx ctx = {
    .in_duplicate = TPM2B_EMPTY_INIT,
    .in_seed = TPM2B_EMPTY_INIT,
    .public_key_data = TPM2B_EMPTY_INIT,
    .key_name = TPM2B_EMPTY_INIT,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .autoflush = false,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.parent.ctx_path = value;
        break;
    case 'p':
        ctx.parent.auth_str = value;
        break;
    case 'k':
        ctx.input_key_file = value;
        break;
    case 's':
        ctx.input_seed_file = value;
        break;
    case 'C':
        ctx.new_parent.ctx_path = value;
        break;
    case 'K':
        ctx.output_key_file = value;
        break;
    case 'S':
        ctx.output_seed_file = value;
        break;
    case 'u':
        ctx.public_key_file = value;
        break;
    case 0:
        ctx.passin = value;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 'R':
        ctx.autoflush = true;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

static tool_rc rewrap(ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    tool_rc rc = tpm2_rewrap(ectx, &ctx.parent.object, &ctx.new_parent.object,
        &ctx.key_name, &ctx.in_duplicate, &ctx.in_seed, &ctx.out_duplicate,
        &ctx.out_seed, &ctx.cp_hash, ctx.parameter_hash_algorithm);
    if (rc != tool_rc_success) {
        return rc;
    }
    if ((ctx.autoflush || tpm2_util_env_yes(TPM2TOOLS_ENV_AUTOFLUSH))) {
        if (ctx.parent.object.path &&
            (ctx.parent.object.handle & TPM2_HR_RANGE_MASK) == TPM2_HR_TRANSIENT) {
            rval = Esys_FlushContext(ectx, ctx.parent.object.tr_handle);
            if (rval != TPM2_RC_SUCCESS) {
                return tool_rc_general_error;
            }
        }
        if (ctx.new_parent.object.path &&
            (ctx.new_parent.object.handle & TPM2_HR_RANGE_MASK) == TPM2_HR_TRANSIENT) {
            rval = Esys_FlushContext(ectx, ctx.new_parent.object.tr_handle);
            if (rval != TPM2_RC_SUCCESS) {
                return tool_rc_general_error;
            }
        }
    }
    return tool_rc_success;
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
    assert(ctx.out_duplicate);
    bool result = files_save_private(ctx.out_duplicate, ctx.output_key_file);
    Esys_Free(ctx.out_duplicate);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.output_key_file);
        return tool_rc_general_error;
    }

    assert(ctx.out_seed);
    if (ctx.output_seed_file) {
        result = files_save_encrypted_seed(ctx.out_seed, ctx.output_seed_file);
    }
    Esys_Free(ctx.out_seed);
    if (!result) {
        LOG_ERR("Failed to save encryption seed into file \"%s\"",
                ctx.output_seed_file);
        return tool_rc_general_error;
    }

    return tool_rc_success;
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false,
            TPM2_HANDLE_FLAGS_REWRAP);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid parent key authorization");
        return rc;
    }

    /* Object #2 */
    rc = tpm2_util_object_load(ectx, ctx.new_parent.ctx_path,
            &ctx.new_parent.object, TPM2_HANDLE_FLAGS_REWRAP);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    bool result = files_load_private(ctx.input_key_file, &ctx.in_duplicate);
    if (!result) {
        LOG_ERR("Failed to load duplicate \"%s\"", ctx.input_key_file);
        return tool_rc_general_error;
    }

    if (ctx.input_seed_file) {
        result = files_load_encrypted_seed(ctx.input_seed_file,
            &ctx.in_seed);
        if (!result) {
            LOG_ERR("Failed to load encrypted seed \"%s\"", ctx.input_seed_file);
            return tool_rc_general_error;
        }
    } else if (ctx.parent.object.handle != TPM2_RH_NULL) {
        LOG_ERR("Expected inSymSeed to be specified via \"-s\","
                " missing option.");
            return tool_rc_general_error;
    }

    result = files_load_public(ctx.public_key_file, &ctx.public_key_data);
    if (!result) {
        LOG_ERR("Failed to load public key \"%s\"", ctx.public_key_file);
        return tool_rc_general_error;
    }

    ctx.key_name = (TPM2B_NAME) TPM2B_TYPE_INIT(TPM2B_NAME, name);
    result = tpm2_identity_create_name(&ctx.public_key_data, &ctx.key_name);
    if (!result) {
        LOG_ERR("Failed to calculate name");
        return tool_rc_general_error;
    }

    /* Sanity check */

    if (ctx.new_parent.object.handle != TPM2_RH_NULL && !ctx.output_seed_file) {
        LOG_ERR("Expected outSymSeed to be specified via \"-S\","
                " missing option.");
        return tool_rc_option_error;
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

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    tool_rc rc = tool_rc_success;

    /* Check the tpm rewrap specific options */

    if (!ctx.parent.ctx_path) {
        LOG_ERR("Expected parent key to be specified via \"-c\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.input_key_file) {
        LOG_ERR("Expected inDuplicate to be specified via \"-k\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    /* inSymSeed checked conditionally in process_inputs() */

    if (!ctx.new_parent.ctx_path) {
        LOG_ERR("Expected new parent key to be specified via \"-C\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.output_key_file) {
        LOG_ERR("Expected outDuplicate to be specified via \"-K\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    /* outSymSeed checked conditionally in process_inputs() */

    if (!ctx.public_key_file) {
        LOG_ERR("Expected public key to be specified via \"-u\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    return rc;
}


static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "parent-context",     required_argument, 0, 'c'},
      { "parent-auth",        required_argument, 0, 'p'},
      { "in-key",             required_argument, 0, 'k'},
      { "in-seed",            required_argument, 0, 's'},
      { "new-parent-context", required_argument, 0, 'C'},
      { "out-key",            required_argument, 0, 'K'},
      { "out-seed",           required_argument, 0, 'S'},
      { "public",             required_argument, 0, 'u'},
      { "passin",             required_argument, 0,  0 },
      { "cphash",             required_argument, 0,  1 },
      { "autoflush",          no_argument,       0, 'R' },
    };

    *opts = tpm2_options_new("c:p:k:s:C:K:S:u:R", ARRAY_LEN(topts),
        topts, on_option, 0, 0);

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
    rc = rewrap(ectx);
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
TPM2_TOOL_REGISTER("rewrap", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
