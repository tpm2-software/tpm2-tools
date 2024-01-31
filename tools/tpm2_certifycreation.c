/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_options.h"

#define MAX_AUX_SESSIONS 2 // one session provided by auth interface
#define MAX_SESSIONS 3
typedef struct tpm_certifycreation_ctx tpm_certifycreation_ctx;
struct tpm_certifycreation_ctx {
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
        tpm2_loaded_object object;
    } certified_key;

    char *creation_hash_path;
    TPM2B_DIGEST creation_hash;

    char *creation_ticket_path;
    TPMT_TK_CREATION creation_ticket;

    TPM2B_DATA policy_qualifier;
    const char *policy_qualifier_data;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    tpm2_convert_sig_fmt sig_format;
    TPMT_SIG_SCHEME in_scheme;

    /*
     * Outputs
     */
    char *signature_path;
    TPMT_SIGNATURE *signature;

    char *certify_info_path;
    TPM2B_ATTEST *certify_info;

   /*
    * Parameter hashes
    */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    TPMI_ALG_HASH parameter_hash_algorithm;
    bool is_command_dispatch;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_certifycreation_ctx ctx = {
        .halg = TPM2_ALG_NULL,
        .sig_scheme = TPM2_ALG_NULL,
        .policy_qualifier = TPM2B_EMPTY_INIT,
        .aux_session_handle[0] = ESYS_TR_NONE,
        .aux_session_handle[1] = ESYS_TR_NONE,
};

static tool_rc certifycreation(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    return tpm2_certifycreation(ectx, &ctx.signing_key.object,
        &ctx.certified_key.object, &ctx.creation_hash, &ctx.in_scheme,
        &ctx.creation_ticket, &ctx.certify_info, &ctx.signature,
        &ctx.policy_qualifier, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0],
        ctx.aux_session_handle[1]);
}

static tool_rc process_output(void) {

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
    is_file_op_success = tpm2_convert_sig_save(ctx.signature, ctx.sig_format,
        ctx.signature_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed saving signature data.");
        return tool_rc_general_error;
    }

    is_file_op_success = files_save_bytes_to_file(ctx.certify_info_path,
        ctx.certify_info->attestationData, ctx.certify_info->size);
    if (!is_file_op_success) {
        LOG_ERR("Failed saving attestation data.");
        return tool_rc_general_error;
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
        ctx.signing_key.auth_str, &ctx.signing_key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid signing key/ authorization.");
        return rc;
    }

    rc = tpm2_util_object_load(ectx, ctx.certified_key.ctx_path,
        &ctx.certified_key.object,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key specified for certification.");
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

     /* Load creation hash */
    rc = files_load_digest(ctx.creation_hash_path, &ctx.creation_hash) ?
        tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        LOG_ERR("Failed loading creation hash.");
        return rc;
    }

    /* Set signature scheme for key type & Validate chosen scheme */
    rc = tpm2_alg_util_get_signature_scheme(ectx,
        ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme,
        &ctx.in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("bad signature scheme for key type!");
        return rc;
    }

    /* Load creation ticket */
    rc = files_load_creation_ticket(ctx.creation_ticket_path,
        &ctx.creation_ticket) ? tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        LOG_ERR("Could not load creation ticket from file");
        return rc;
    }

    /* Qualifier data is optional. If not specified default to 0 */
    if (ctx.policy_qualifier_data) {
        ctx.policy_qualifier.size = sizeof(ctx.policy_qualifier.buffer);

        rc = tpm2_util_bin_from_hex_or_file(ctx.policy_qualifier_data,
            &ctx.policy_qualifier.size, ctx.policy_qualifier.buffer) ?
            tool_rc_success : tool_rc_general_error;

        if (rc != tool_rc_success) {
            LOG_ERR("Could not load qualifier data");
            return rc;
        }
    }
    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.certified_key.object.session,
        ctx.aux_session[0],
        ctx.aux_session[1]
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

static bool check_options(void) {

    if (ctx.cp_hash_path && !ctx.rp_hash_path &&
        (ctx.certify_info_path || ctx.signature_path)) {
        LOG_ERR("Cannot generate outputs when calculating cpHash.");
        return false;
    }

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Must specify the signing key '-C'.");
        return false;
    }

    if (!ctx.certified_key.ctx_path) {
        LOG_ERR("Must specify the path of the key to certify '-c'.");
        return false;
    }

    if (!ctx.creation_ticket_path) {
        LOG_ERR("Must specify the creation ticket path '-t'.");
        return false;
    }

    if (!ctx.signature_path && !ctx.cp_hash_path) {
        LOG_ERR("Must specify the file path to save signature '-o'");
        return false;
    }

    if (!ctx.certify_info_path && !ctx.cp_hash_path) {
        LOG_ERR("Must specify file path to save attestation '--attestation'");
        return false;
    }

    return true;
}

static bool set_signature_format(char *value) {

    ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);
    if (ctx.sig_format == signature_format_err) {
        return false;
    }
    return true;
}

static bool set_signing_scheme(char *value) {

    ctx.sig_scheme = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
    if (ctx.sig_scheme == TPM2_ALG_ERROR) {
        LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
        return false;
    }
    return true;
}

static bool set_digest_algorithm(char *value) {

    ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
    if (ctx.halg == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert to number or lookup algorithm, got: "
                "\"%s\"", value);
        return false;
    }
    return true;
}

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'C':
        ctx.signing_key.ctx_path = value;
        break;
    case 'P':
        ctx.signing_key.auth_str = value;
        break;
    case 'c':
        ctx.certified_key.ctx_path = value;
        break;
    case 'd':
        ctx.creation_hash_path = value;
        break;
    case 't':
        ctx.creation_ticket_path = value;
        break;
    case 'g':
        result = set_digest_algorithm(value);
        goto on_option_out;
    case 's':
        result = set_signing_scheme(value);
        goto on_option_out;
    case 'f':
        result = set_signature_format(value);
        goto on_option_out;
    case 'o':
        ctx.signature_path = value;
        break;
    case 0:
        ctx.certify_info_path = value;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 2:
        ctx.rp_hash_path = value;
        break;
    case 'q':
        ctx.policy_qualifier_data = value;
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
        /* no default */
    }

on_option_out:
    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "signingkey-context",   required_argument, NULL, 'C' },
      { "signingkey-auth",      required_argument, NULL, 'P' },
      { "certifiedkey-context", required_argument, NULL, 'c' },
      { "creation-hash",        required_argument, NULL, 'd' },
      { "ticket",               required_argument, NULL, 't' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "scheme",               required_argument, NULL, 's' },
      { "format",               required_argument, NULL, 'f' },
      { "signature",            required_argument, NULL, 'o' },
      { "attestation",          required_argument, NULL,  0  },
      { "qualification",        required_argument, NULL, 'q' },
      { "cphash",               required_argument, NULL,  1  },
      { "rphash",               required_argument, NULL,  2  },
      { "session",              required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("C:P:c:d:t:g:s:f:o:q:S:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    bool result = check_options();
    if (!result) {
        return tool_rc_option_error;
    }

   /*
     * 2. Process inputs
     */
    tool_rc rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = certifycreation(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    rc = process_output();

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    Esys_Free(ctx.signature);
    Esys_Free(ctx.certify_info);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.signing_key.object.session);
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
TPM2_TOOL_REGISTER("certifycreation", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
