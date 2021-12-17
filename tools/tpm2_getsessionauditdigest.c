/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"
#include "tpm2_tool.h"

typedef struct tpm_getsessionauditdigest_ctx tpm_getsessionauditdigest_ctx;
struct tpm_getsessionauditdigest_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } endorsement_hierarchy;

    char *signature_path;
    char *message_path;
    tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    TPM2B_DATA qualification_data;
    TPM2B_ATTEST *audit_info;
    TPMT_SIGNATURE *signature;
    TPMT_SIG_SCHEME in_scheme;

    tpm2_session *audit_session;
    const char *audit_session_path;
    ESYS_TR audit_session_handle;
};

static tpm_getsessionauditdigest_ctx ctx = {
    .sig_hash_algorithm = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .qualification_data = TPM2B_EMPTY_INIT,
    .endorsement_hierarchy = {
        .ctx_path = "e"
    },
    .in_scheme = {
        .scheme = TPM2_ALG_NULL,
    },
    .audit_session_handle = ESYS_TR_NONE,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.endorsement_hierarchy.auth_str = value;
        break;
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
        break;
    case 'q':
        ctx.qualification_data.size = sizeof(ctx.qualification_data.buffer);
        return tpm2_util_bin_from_hex_or_file(value, &ctx.qualification_data.size,
                ctx.qualification_data.buffer);
        break;
    case 's':
        ctx.signature_path = value;
        break;
    case 'm':
        ctx.message_path = value;
        break;
    case 'f':
        ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
        break;
    case 'g':
        ctx.sig_hash_algorithm = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_hash);
        if (ctx.sig_hash_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR(
                    "Could not convert signature hash algorithm selection, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 0:
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
        break;
    case 'S':
        ctx.audit_session_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "hierarchy-auth", required_argument, NULL, 'P' },
        { "key-context",    required_argument, NULL, 'c' },
        { "auth",           required_argument, NULL, 'p' },
        { "qualification",  required_argument, NULL, 'q' },
        { "signature",      required_argument, NULL, 's' },
        { "message",        required_argument, NULL, 'm' },
        { "format",         required_argument, NULL, 'f' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "scheme",         required_argument, NULL,  0  },
        { "session",        required_argument, NULL, 'S' }
    };

    *opts = tpm2_options_new("S:P:c:p:q:s:m:f:g:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static bool check_input_options_and_args(void) {

    if (!ctx.key.ctx_path) {
        LOG_ERR("Specify the signing key to use for signing attestation.");
        return false;
    }

    if (!ctx.signature_path) {
        LOG_ERR("Specify the file path to store the signature of the attestation data.");
        return false;
    }

    if (!ctx.message_path) {
        LOG_ERR("Specify the file path to store the attestation data.");
        return false;
    }

    if (!ctx.audit_session_path) {
        LOG_ERR("Specify the session to be used to start audit.");
        return false;
    }

    return true;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_session_restore(ectx, ctx.audit_session_path,
        false, &ctx.audit_session);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not restore audit session");
        return rc;
    }
    ctx.audit_session_handle = tpm2_session_get_handle(ctx.audit_session);

    /*
     * Load auths
     */
    rc = tpm2_util_object_load_auth(ectx,
        ctx.endorsement_hierarchy.ctx_path, ctx.endorsement_hierarchy.auth_str,
        &ctx.endorsement_hierarchy.object, false, TPM2_HANDLE_FLAGS_E);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid endorsement hierarchy authorization");
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
            ctx.key.auth_str, &ctx.key.object, false,
            TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    /*
     * Setup signature scheme
     */
    rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.key.object.tr_handle, &ctx.sig_hash_algorithm, TPM2_ALG_NULL,
            &ctx.in_scheme);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tool_rc_success;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    bool result = true;
    if (ctx.signature_path) {
        result = tpm2_convert_sig_save(ctx.signature, ctx.sig_format,
                ctx.signature_path);
    }
    if (!result) {
        LOG_ERR("Failed to save the signature data.");
        return tool_rc_general_error;
    }

    if (ctx.message_path) {
        result = files_save_bytes_to_file(ctx.message_path,
                (UINT8*) ctx.audit_info->attestationData, ctx.audit_info->size);
    }
    if (!result) {
        LOG_ERR("Failed to save the attestation data.");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    //Check input arguments
    bool result = check_input_options_and_args();
    if (!result) {
        return tool_rc_option_error;
    }

    //Process inputs
    tool_rc rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    //ESAPI call
    rc = tpm2_getsessionauditdigest(ectx, &ctx.endorsement_hierarchy.object,
    &ctx.key.object, &ctx.in_scheme, &ctx.qualification_data, &ctx.audit_info,
    &ctx.signature, ctx.audit_session_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    //Process Outputs
    rc = process_outputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    tool_rc rc = tpm2_session_close(&ctx.audit_session);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed closing audit session.");
    }

    rc = tpm2_session_close(&ctx.key.object.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed closing auth session for signing key handle.");
    }

    rc = tpm2_session_close(&ctx.endorsement_hierarchy.object.session);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed closing auth session for endorsement hierarchy handle.");
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("getsessionauditdigest", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
