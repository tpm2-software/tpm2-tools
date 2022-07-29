/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_options.h"

typedef struct tpm_certify_ctx tpm_certify_ctx;
#define MAX_AUX_SESSIONS 1 // two sessions provided by auth interface
#define MAX_SESSIONS 3
struct tpm_certify_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } certified_key;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    TPMI_ALG_HASH halg;
    tpm2_convert_sig_fmt sig_fmt;
    TPMT_SIG_SCHEME scheme;
    TPMI_ALG_SIG_SCHEME sig_scheme;

    /*
     * Outputs
    */
    struct {
        char *attest;
        char *sig;
    } file_path;
    TPM2B_ATTEST *certify_info;
    TPMT_SIGNATURE *signature;

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

static tpm_certify_ctx ctx = {
    .sig_fmt = signature_format_tss,
    .halg = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .aux_session_handle[0] = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .scheme = {
        .scheme = TPM2_ALG_NULL,
    }
};

static tool_rc certify(ESYS_CONTEXT *ectx) {

    TPM2B_DATA qualifying_data = {
        .size = 4,
        .buffer = { 0x00, 0xff, 0x55,0xaa },
    };

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */

    return tpm2_certify(ectx, &ctx.certified_key.object,
        &ctx.signing_key.object, &qualifying_data, &ctx.scheme,
        &ctx.certify_info, &ctx.signature, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0]);
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

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }
    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    /* serialization is safe here, since it's just a byte array */
    is_file_op_success = files_save_bytes_to_file(ctx.file_path.attest,
        ctx.certify_info->attestationData, ctx.certify_info->size);
    if (!is_file_op_success) {
         goto out;
     }

    is_file_op_success = tpm2_convert_sig_save(ctx.signature, ctx.sig_fmt,
        ctx.file_path.sig);
    if (!is_file_op_success) {
        goto out;
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

out:
    free(ctx.certify_info);
    free(ctx.signature);

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
    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.certified_key.ctx_path,
        ctx.certified_key.auth_str, &ctx.certified_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Object #2 */
    rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
        ctx.signing_key.auth_str, &ctx.signing_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
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
     * 3. Command specific initializations
     */
    rc = tpm2_alg_util_get_signature_scheme(ectx,
        ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme,
        &ctx.scheme);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.certified_key.object.session,
        ctx.signing_key.object.session,
        ctx.aux_session[0]
    };

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

    return rc;
}

static tool_rc check_options(void) {

    if ((!ctx.certified_key.ctx_path) && (!ctx.signing_key.ctx_path)) {
        LOG_ERR("Must specify the object to be certified and the signing key.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && !ctx.rp_hash_path &&
       (ctx.file_path.attest || ctx.file_path.sig)) {
        LOG_ERR("Cannot specify output options when calculating cpHash");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.certified_key.ctx_path = value;
        break;
    case 'C':
        ctx.signing_key.ctx_path = value;
        break;
    case 'P':
        ctx.certified_key.auth_str = value;
        break;
    case 'p':
        ctx.signing_key.auth_str = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not format algorithm to number, got: \"%s\"", value);
            return false;
        }
        break;
    case 'o':
        ctx.file_path.attest = value;
        break;
    case 's':
        ctx.file_path.sig = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.rp_hash_path = value;
        break;
    case 2:
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
        break;
    case 'f':
        ctx.sig_fmt = tpm2_convert_sig_fmt_from_optarg(value);
        if (ctx.sig_fmt == signature_format_err) {
            return false;
        }
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

    const struct option topts[] = {
      { "certifiedkey-context", required_argument, NULL, 'c' },
      { "signingkey-context",   required_argument, NULL, 'C' },
      { "certifiedkey-auth",    required_argument, NULL, 'P' },
      { "signingkey-auth",      required_argument, NULL, 'p' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "attestation",          required_argument, NULL, 'o' },
      { "signature",            required_argument, NULL, 's' },
      { "format",               required_argument, NULL, 'f' },
      { "cphash",               required_argument, NULL,  0  },
      { "rphash",               required_argument, NULL,  1  },
      { "scheme",               required_argument, NULL,  2  },
      { "session",              required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("P:p:g:o:s:c:C:f:S:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

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
    rc = certify(ectx);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.signing_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.certified_key.object.session);
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
TPM2_TOOL_REGISTER("certify", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
