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

typedef struct tpm_certifycreation_ctx tpm_certifycreation_ctx;
struct tpm_certifycreation_ctx {
    TPMT_TK_CREATION creation_ticket;
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

    char *creation_ticket_path;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    tpm2_convert_sig_fmt sig_format;
    char *signature_path;

    char *certify_info_path;

    const char *policy_qualifier_data;

    char *cp_hash_path;
};

static tpm_certifycreation_ctx ctx = {
        .halg = TPM2_ALG_NULL,
        .sig_scheme = TPM2_ALG_NULL
};

static bool set_digest_algorithm(char *value) {

    ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
    if (ctx.halg == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert to number or lookup algorithm, got: "
                "\"%s\"", value);
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

static bool set_signature_format(char *value) {

    ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);
    if (ctx.sig_format == signature_format_err) {
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
    case 'q':
        ctx.policy_qualifier_data = value;
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
    };

    *opts = tpm2_options_new("C:P:c:d:t:g:s:f:o:q:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static bool is_input_options_args_valid(void) {

    if (ctx.cp_hash_path && (ctx.certify_info_path || ctx.signature_path)) {
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

static tool_rc process_certifycreation_input(ESYS_CONTEXT *ectx,
    TPM2B_DIGEST *creation_hash, TPMT_SIG_SCHEME *in_scheme,
    TPMT_TK_CREATION *creation_ticket, TPM2B_DATA *policy_qualifier) {

    /*
     * Load objects and auths
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
     * Load creation hash
     */
    bool result = files_load_digest(ctx.creation_hash_path, creation_hash);
    if (!result) {
        LOG_ERR("Failed loading creation hash.");
        return tool_rc_general_error;
    }

    /*
     * Set signature scheme for key type
     * Validate chosen scheme is allowed for key type
     */
    rc = tpm2_alg_util_get_signature_scheme(ectx,
        ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme, in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("bad signature scheme for key type!");
        return rc;
    }

    /*
     * Load creation ticket
     */
    result = files_load_creation_ticket(ctx.creation_ticket_path,
        creation_ticket);
    if (!result) {
        LOG_ERR("Could not load creation ticket from file");
        return tool_rc_general_error;
    }

    /*
     * Qualifier data is optional. If not specified default to 0
     */
    if (!ctx.policy_qualifier_data) {
        return tool_rc_success;
    }

    policy_qualifier->size = sizeof(policy_qualifier->buffer);
    result = tpm2_util_bin_from_hex_or_file(ctx.policy_qualifier_data,
            &policy_qualifier->size, policy_qualifier->buffer);

    return result ? tool_rc_success : tool_rc_general_error;;
}

static tool_rc process_certifycreation_output(TPMT_SIGNATURE *signature,
    TPM2B_ATTEST *certify_info) {

    bool result = tpm2_convert_sig_save(signature, ctx.sig_format,
        ctx.signature_path);
    if (!result) {
        LOG_ERR("Failed saving signature data.");
        return tool_rc_general_error;
    }

    result = files_save_bytes_to_file(ctx.certify_info_path,
        certify_info->attestationData, certify_info->size);
    if (!result) {
        LOG_ERR("Failed saving attestation data.");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = is_input_options_args_valid();
    if (!result) {
        return tool_rc_option_error;
    }

    //Input
    TPM2B_DIGEST creation_hash;
    TPMT_SIG_SCHEME in_scheme;
    TPMT_TK_CREATION creation_ticket;
    TPM2B_DATA policy_qualifier = TPM2B_EMPTY_INIT;
    tool_rc rc = process_certifycreation_input(ectx, &creation_hash, &in_scheme,
        &creation_ticket, &policy_qualifier);
    if (rc != tool_rc_success) {
        return rc;
    }

    //ESAPI call
    TPMT_SIGNATURE *signature = NULL;
    TPM2B_ATTEST *certify_info = NULL;
    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        rc = tpm2_certifycreation(ectx, &ctx.signing_key.object,
        &ctx.certified_key.object, &creation_hash, &in_scheme, &creation_ticket,
        &certify_info, &signature, &policy_qualifier, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    rc = tpm2_certifycreation(ectx, &ctx.signing_key.object,
        &ctx.certified_key.object, &creation_hash, &in_scheme, &creation_ticket,
        &certify_info, &signature, &policy_qualifier, NULL);
    if (rc != tool_rc_success) {
        goto tpm2_tool_onrun_out;
    }

    //Output
    rc = process_certifycreation_output(signature, certify_info);

tpm2_tool_onrun_out:
    Esys_Free(signature);
    Esys_Free(certify_info);
    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.signing_key.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("certifycreation", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
