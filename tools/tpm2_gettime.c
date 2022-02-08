/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_gettime_ctx tpm_gettime_ctx;
struct tpm_gettime_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } privacy_admin;

    TPM2B_DATA qualifying_data;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    TPMT_SIG_SCHEME in_scheme;

    /*
     * Outputs
     */
    const char *certify_info_path;
    TPM2B_ATTEST *time_info;

    const char *output_path;
    TPMT_SIGNATURE *signature;
    tpm2_convert_sig_fmt sig_format;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_gettime_ctx ctx = {
    .halg = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .privacy_admin = { .ctx_path = "endorsement" },
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc gettime(ESYS_CONTEXT *ectx) {

    return tpm2_gettime(ectx, &ctx.privacy_admin.object,
        &ctx.signing_key.object, &ctx.qualifying_data, &ctx.in_scheme,
        &ctx.time_info,&ctx.signature, &ctx.cp_hash,
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
    /* save the signature */
    if (ctx.output_path) {
        is_file_op_success = tpm2_convert_sig_save(ctx.signature,
            ctx.sig_format, ctx.output_path);
        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    if (ctx.certify_info_path) {
        /* save the attestation data */
        is_file_op_success = files_save_bytes_to_file(ctx.certify_info_path,
            ctx.time_info->attestationData, ctx.time_info->size);
        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    TPMS_ATTEST attest;
    rc = files_tpm2b_attest_to_tpms_attest(ctx.time_info, &attest);
    if (rc == tool_rc_success) {
        tpm2_util_print_time(&attest.attested.time.time);
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
     */

    /* Object #1 */
    /* set up the privacy admin (always endorsement) hard coded in ctx init */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.privacy_admin.ctx_path,
        ctx.privacy_admin.auth_str, &ctx.privacy_admin.object, false,
        TPM2_HANDLE_FLAGS_E);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Object #2 */
    /* load the signing key */
    rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
        ctx.signing_key.auth_str, &ctx.signing_key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    /*
     * Set signature scheme for key type, or validate chosen scheme is allowed for key type.
     */
    rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme,
            &ctx.in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("bad signature scheme for key type!");
        return rc;
    }

    /*
     * 4. Configuration for calculating the pHash
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.privacy_admin.object.session,
        ctx.signing_key.object.session,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.a Determine pHash length and alg
     */

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;
    if (!ctx.is_command_dispatch && (ctx.output_path || ctx.certify_info_path)) {
        LOG_ERR("Ignoring output options due to cpHash calculation");
        return tool_rc_option_error;
    }

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Expected option \"-c\"");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.signing_key.ctx_path = value;
        break;
    case 'p':
        ctx.signing_key.auth_str = value;
        break;
    case 'P':
        ctx.privacy_admin.auth_str = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert to number or lookup algorithm, got: "
                    "\"%s\"", value);
            return false;
        }
        break;
    case 's': {
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
    }
        break;
    case 'o':
        ctx.output_path = value;
        break;
    case 'f':
        ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
        break;
    case 'q':
        ctx.qualifying_data.size = sizeof(ctx.qualifying_data.buffer);
        return tpm2_util_bin_from_hex_or_file(value, &ctx.qualifying_data.size,
                ctx.qualifying_data.buffer);
        break;
    case 2:
        ctx.certify_info_path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth",           required_argument, 0, 'p' },
      { "endorse-auth",   required_argument, 0, 'P' },
      { "hash-algorithm", required_argument, 0, 'g' },
      { "scheme",         required_argument, 0, 's' },
      { "signature",      required_argument, 0, 'o' },
      { "key-context",    required_argument, 0, 'c' },
      { "format",         required_argument, 0, 'f' },
      { "qualification",  required_argument, 0, 'q' },
      { "attestation",    required_argument, 0,  2  },
      { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("p:g:o:c:f:s:P:q:", ARRAY_LEN(topts), topts,
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
    rc = gettime(ectx);
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
    Esys_Free(ctx.time_info);
    Esys_Free(ctx.signature);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.privacy_admin.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.signing_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("gettime", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
