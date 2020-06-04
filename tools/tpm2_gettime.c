/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"

typedef struct tpm_gettime_ctx tpm_gettime_ctx;
struct tpm_gettime_ctx {
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

    tpm2_convert_sig_fmt sig_format;
    TPM2B_DATA qualifying_data;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    TPMT_SIG_SCHEME in_scheme;

    const char *certify_info_path;
    const char *output_path;

    char *cp_hash_path;
};

static tpm_gettime_ctx ctx = {
        .halg = TPM2_ALG_NULL,
        .sig_scheme = TPM2_ALG_NULL,
        .privacy_admin = { .ctx_path = "endorsement" }
};

static tool_rc init(ESYS_CONTEXT *ectx) {

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Expected option \"-c\"");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && (ctx.output_path || ctx.certify_info_path)) {
        LOG_ERR("Ignoring output options due to cpHash calculation");
        return tool_rc_option_error;
    }

    /* load the signing key */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
            ctx.signing_key.auth_str, &ctx.signing_key.object, false,
            TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

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

    /* set up the privacy admin (always endorsement) hard coded in ctx init */
    rc = tpm2_util_object_load_auth(ectx, ctx.privacy_admin.ctx_path,
            ctx.privacy_admin.auth_str, &ctx.privacy_admin.object, false,
            TPM2_HANDLE_FLAGS_E);
    if (rc != tool_rc_success) {
        return rc;
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
      { "auth",                 required_argument, NULL, 'p' },
      { "endorse-auth",         required_argument, NULL, 'P' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "scheme",               required_argument, NULL, 's' },
      { "signature",            required_argument, NULL, 'o' },
      { "key-context",          required_argument, NULL, 'c' },
      { "format",               required_argument, NULL, 'f' },
      { "qualification",        required_argument, NULL, 'q' },
      { "attestation",          required_argument, NULL,  2  },
      { "cphash",               required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("p:g:o:c:f:s:P:q:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPM2B_ATTEST *time_info = NULL;
    TPMT_SIGNATURE *signature = NULL;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_gettime(ectx, &ctx.privacy_admin.object,
        &ctx.signing_key.object, &ctx.qualifying_data, &ctx.in_scheme,
        &time_info, &signature, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }

        return rc;
    }

    rc = tpm2_gettime(ectx,
            &ctx.privacy_admin.object,
            &ctx.signing_key.object,
            &ctx.qualifying_data,
            &ctx.in_scheme,
            &time_info,
            &signature,
            NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* save the signature */
    if (ctx.output_path) {
        bool result = tpm2_convert_sig_save(signature, ctx.sig_format, ctx.output_path);
        if (!result) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    if (ctx.certify_info_path) {
        /* save the attestation data */
        bool result = files_save_bytes_to_file(ctx.certify_info_path,
            time_info->attestationData, time_info->size);
        if (!result) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    TPMS_ATTEST attest;
    rc = files_tpm2b_attest_to_tpms_attest(time_info, &attest);
    if (rc == tool_rc_success) {
        tpm2_util_print_time(&attest.attested.time.time);
    }

out:
    Esys_Free(time_info);
    Esys_Free(signature);
    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    tool_rc rc = tpm2_session_close(&ctx.privacy_admin.object.session);
    rc |=tpm2_session_close(&ctx.signing_key.object.session);

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("gettime", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
