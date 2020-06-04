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
struct tpm_certify_ctx {
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

    struct {
        char *attest;
        char *sig;
    } file_path;

    struct {
        UINT16 g :1;
        UINT16 o :1;
        UINT16 s :1;
        UINT16 f :1;
    } flags;

    TPMI_ALG_HASH halg;
    tpm2_convert_sig_fmt sig_fmt;

    char *cp_hash_path;
};

static tpm_certify_ctx ctx = {
    .sig_fmt = signature_format_tss,
};

static tool_rc get_key_type(ESYS_CONTEXT *ectx, ESYS_TR object_handle,
        TPMI_ALG_PUBLIC *type) {

    TPM2B_PUBLIC *out_public = NULL;
    tool_rc rc = tpm2_readpublic(ectx, object_handle, &out_public, NULL, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    *type = out_public->publicArea.type;

    free(out_public);

    return tool_rc_success;
}

static tool_rc set_scheme(ESYS_CONTEXT *ectx, ESYS_TR key_handle,
        TPMI_ALG_HASH halg, TPMT_SIG_SCHEME *scheme) {

    TPM2_ALG_ID type;
    tool_rc rc = get_key_type(ectx, key_handle, &type);
    if (rc != tool_rc_success) {
        return rc;
    }

    switch (type) {
    case TPM2_ALG_RSA:
        scheme->scheme = TPM2_ALG_RSASSA;
        scheme->details.rsassa.hashAlg = halg;
        break;
    case TPM2_ALG_KEYEDHASH:
        scheme->scheme = TPM2_ALG_HMAC;
        scheme->details.hmac.hashAlg = halg;
        break;
    case TPM2_ALG_ECC:
        scheme->scheme = TPM2_ALG_ECDSA;
        scheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM2_ALG_SYMCIPHER:
    default:
        LOG_ERR("Unknown key type, got: 0x%x", type);
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc certify_and_save_data(ESYS_CONTEXT *ectx) {

    TPM2B_DATA qualifying_data = {
        .size = 4,
        .buffer = { 0x00, 0xff, 0x55,0xaa }
    };

    tool_rc rc = tool_rc_general_error;

    TPMT_SIG_SCHEME scheme;
    tool_rc tmp_rc = set_scheme(ectx, ctx.signing_key.object.tr_handle,
            ctx.halg, &scheme);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("No suitable signing scheme!");
        return tmp_rc;
    }

    TPM2B_ATTEST *certify_info;
    TPMT_SIGNATURE *signature;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_certify(ectx, &ctx.certified_key.object,
        &ctx.signing_key.object, &qualifying_data, &scheme, &certify_info,
        &signature, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }

        return rc;
    }

    tmp_rc = tpm2_certify(ectx, &ctx.certified_key.object,
            &ctx.signing_key.object, &qualifying_data, &scheme, &certify_info,
            &signature, NULL);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }
    /* serialization is safe here, since it's just a byte array */
    bool result = files_save_bytes_to_file(ctx.file_path.attest,
            certify_info->attestationData, certify_info->size);
    if (!result) {
        goto out;
    }

    result = tpm2_convert_sig_save(signature, ctx.sig_fmt, ctx.file_path.sig);
    if (!result) {
        goto out;
    }

    rc = tool_rc_success;

out:
    free(certify_info);
    free(signature);

    return rc;
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
        ctx.flags.g = 1;
        break;
    case 'o':
        ctx.file_path.attest = value;
        ctx.flags.o = 1;
        break;
    case 's':
        ctx.file_path.sig = value;
        ctx.flags.s = 1;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 'f':
        ctx.flags.f = 1;
        ctx.sig_fmt = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_fmt == signature_format_err) {
            return false;
        }
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "certifiedkey-context", required_argument, NULL, 'c' },
      { "signingkey-context",   required_argument, NULL, 'C' },
      { "certifiedkey-auth",    required_argument, NULL, 'p' },
      { "signingkey-auth",      required_argument, NULL, 'P' },
      { "hash-algorithm",       required_argument, NULL, 'g' },
      { "attestation",          required_argument, NULL, 'o' },
      { "signature",            required_argument, NULL, 's' },
      { "format",               required_argument, NULL, 'f' },
      { "cphash",               required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("P:p:g:o:s:c:C:f:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    if ((!ctx.certified_key.ctx_path) && (!ctx.signing_key.ctx_path)
            && (ctx.flags.g) && (ctx.flags.o) && (ctx.flags.s)) {
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && (ctx.file_path.attest || ctx.file_path.sig)) {
        LOG_ERR("Cannot specify output options when calculating cpHash");
        return tool_rc_option_error;
    }

    /* Load input files */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.certified_key.ctx_path,
            ctx.certified_key.auth_str, &ctx.certified_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
            ctx.signing_key.auth_str, &ctx.signing_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    return certify_and_save_data(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    tool_rc rc = tool_rc_success;

    tool_rc tmp_rc = tpm2_session_close(&ctx.signing_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.certified_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("certify", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
