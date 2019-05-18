/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "tpm2_convert.h"
#include "tpm2_options.h"
#include "tpm2_auth_util.h"
#include "files.h"
#include "log.h"
#include "tpm2_util.h"
#include "tpm2_session.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_capability.h"

typedef struct createak_context createak_context;
struct createak_context {
    struct {
        const char *ctx_arg;
        tpm2_loaded_object ek_ctx;
        tpm2_session *session;
        char *auth_str;
    } ek;
    struct {
        struct {
            TPM2B_SENSITIVE_CREATE inSensitive;
            struct {
                TPM2_ALG_ID type;
                TPM2_ALG_ID digest;
                TPM2_ALG_ID sign;
            } alg;
        } in;
        struct {
            const char *ctx_file;
            tpm2_convert_pubkey_fmt pub_fmt;
            const char *pub_file;
            const char *name_file;
            const char *priv_file;
        } out;
        char *auth_str;
    } ak;
    struct {
        UINT8 f : 1;
    } flags;
};

static createak_context ctx = {
    .ak = {
        .in = {
            .alg = {
                .type = TPM2_ALG_RSA,
                .digest = TPM2_ALG_SHA256,
                .sign = TPM2_ALG_NULL
            },
        },
        .out = {
            .pub_fmt = pubkey_format_tss
        },
    },
    .flags = { 0 },
};

/*
 * TODO: All these set_xxx_signing_algorithm() routines could likely somehow be refactored into one.
 */
static bool set_rsa_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg, TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_RSASSA;
    }

    in_public->publicArea.parameters.rsaDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_RSASSA :
    case TPM2_ALG_RSAPSS :
        in_public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The RSA signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_ecc_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_ECDSA;
    }

    in_public->publicArea.parameters.eccDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_ECDSA :
    case TPM2_ALG_SM2 :
    case TPM2_ALG_ECSCHNORR :
    case TPM2_ALG_ECDAA :
        in_public->publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The ECC signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_keyed_hash_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_HMAC;
    }

    in_public->publicArea.parameters.keyedHashDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_HMAC :
        in_public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR(
                "The Keyedhash signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_key_algorithm(TPM2B_PUBLIC *in_public)
{
    in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
    // First clear attributes bit field.
    in_public->publicArea.objectAttributes = 0;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    in_public->publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public->publicArea.authPolicy.size = 0;

    in_public->publicArea.type = ctx.ak.in.alg.type;

    switch(ctx.ak.in.alg.type)
    {
    case TPM2_ALG_RSA:
        in_public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        in_public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.keyBits = 2048;
        in_public->publicArea.parameters.rsaDetail.exponent = 0;
        in_public->publicArea.unique.rsa.size = 0;
        return set_rsa_signing_algorithm(ctx.ak.in.alg.sign, ctx.ak.in.alg.digest, in_public);
    case TPM2_ALG_ECC:
        in_public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
        in_public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        in_public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        in_public->publicArea.unique.ecc.x.size = 0;
        in_public->publicArea.unique.ecc.y.size = 0;
        return set_ecc_signing_algorithm(ctx.ak.in.alg.sign, ctx.ak.in.alg.digest, in_public);
    case TPM2_ALG_KEYEDHASH:
        in_public->publicArea.unique.keyedHash.size = 0;
        return set_keyed_hash_signing_algorithm(ctx.ak.in.alg.sign, ctx.ak.in.alg.digest, in_public);
    case TPM2_ALG_SYMCIPHER:
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx.ak.in.alg.type);
        return false;
    }

    return true;
}

static tool_rc create_ak(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_general_error;

    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *out_public;
    TPM2B_PRIVATE *out_private;
    TPM2B_PUBLIC inPublic = TPM2B_EMPTY_INIT;

    bool result = set_key_algorithm(&inPublic);
    if (!result) {
        return false;
    }

    tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_open(ectx, data);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    ESYS_TR sess_handle = tpm2_session_get_handle(session);

    ESYS_TR shandle = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_ENDORSEMENT,
                        ctx.ek.session);
    if (shandle == ESYS_TR_NONE) {
        goto out_session;
    }

    TPM2_RC rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle,
                    shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        goto out_session;
    }

    LOG_INFO("Esys_PolicySecret success");

    rval = Esys_Create(ectx, ctx.ek.ek_ctx.tr_handle,
                sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                &ctx.ak.in.inSensitive, &inPublic, &outsideInfo,
                &creation_pcr, &out_private, &out_public, NULL, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Create, rval);
        goto out;
    }
    LOG_INFO("Esys_Create success");

    result = tpm2_session_close(&session);
    if (!result) {
        goto out;
    }

    data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        goto out;
    }

    session = tpm2_session_open(ectx, data);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        goto out;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    sess_handle = tpm2_session_get_handle(session);

    shandle = tpm2_auth_util_get_shandle(ectx, sess_handle,
                ctx.ek.session);
    if (shandle == ESYS_TR_NONE) {
        goto out;
    }

    rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle,
                shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        goto out;
    }
    LOG_INFO("Esys_PolicySecret success");

    ESYS_TR loaded_sha1_key_handle;
    rval = Esys_Load(ectx, ctx.ek.ek_ctx.tr_handle,
                sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                out_private, out_public, &loaded_sha1_key_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Load, rval);
        rc = tool_rc_from_tpm(rval);
        goto out;
    }

    // Load the TPM2 handle so that we can print it
    TPM2B_NAME *key_name;
    rval = Esys_TR_GetName(ectx, loaded_sha1_key_handle, &key_name);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_GetName, rval);
        rc = tool_rc_from_tpm(rval);
        goto nameout;
    }

    result = tpm2_session_close(&session);
    if (!result) {
        goto out;
    }

    /* Output in YAML format */
    tpm2_tool_output("loaded-key:\n  name: ");
    tpm2_util_print_tpm2b((TPM2B *)key_name);
    tpm2_tool_output("\n");

    // write name to ak.name file
    if (ctx.ak.out.name_file) {
        result = files_save_bytes_to_file(ctx.ak.out.name_file,
                    key_name->name, key_name->size);
        if (!result) {
            LOG_ERR("Failed to save AK name into file \"%s\"",
                        ctx.ak.out.name_file);
            goto nameout;
        }
    }

    // If the AK isn't persisted we always save a context file of the
    // transient AK handle for future tool interactions.
    result = files_save_tpm_context_to_path(ectx,
                loaded_sha1_key_handle, ctx.ak.out.ctx_file);
    if (!result) {
        LOG_ERR("Error saving tpm context for handle");
        goto nameout;
    }

    if (ctx.ak.out.pub_file) {
        result = tpm2_convert_pubkey_save(out_public, ctx.ak.out.pub_fmt,
                ctx.ak.out.pub_file);
        if (!result) {
            goto nameout;
        }
    }

    if (ctx.ak.out.priv_file) {
        result = files_save_private(out_private, ctx.ak.out.priv_file);
        if (!result) {
            goto nameout;
        }
    }

    rc = tool_rc_success;

nameout:
    free(key_name);
out:
    free(out_public);
    free(out_private);
out_session:
    tpm2_session_close(&session);

    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.ek.ctx_arg = value;
        break;
    case 'G':
        ctx.ak.in.alg.type = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_base);
        if (ctx.ak.in.alg.type == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert algorithm. got: \"%s\".", value);
            return false;
        }
        break;
    case 'D':
        ctx.ak.in.alg.digest = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.ak.in.alg.digest == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert digest algorithm.");
            return false;
        }
        break;
    case 's':
        ctx.ak.in.alg.sign = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
        if (ctx.ak.in.alg.sign == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert signing algorithm.");
            return false;
        }
        break;
    case 'e':
        ctx.ek.auth_str = value;
        break;
    case 'P':
        ctx.ak.auth_str = value;
        break;
    case 'p':
        ctx.ak.out.pub_file = value;
        break;
    case 'n':
        ctx.ak.out.name_file = value;
        break;
    case 'f':
        ctx.ak.out.pub_fmt = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.ak.out.pub_fmt == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = true;
        break;
    case 'c':
        ctx.ak.out.ctx_file = value;
        break;
    case 'r':
        ctx.ak.out.priv_file = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-endorse",   required_argument, NULL, 'e' },
        { "auth-ak",        required_argument, NULL, 'P' },
        { "ek-context",     required_argument, NULL, 'C' },
        { "algorithm",      required_argument, NULL, 'G' },
        { "digest-alg",     required_argument, NULL, 'D' },
        { "sign-alg",       required_argument, NULL, 's' },
        { "file",           required_argument, NULL, 'p' },
        { "ak-name",        required_argument, NULL, 'n' },
        { "format",         required_argument, NULL, 'f' },
        { "context",        required_argument, NULL, 'c' },
        { "privfile",       required_argument, NULL, 'r'},
    };

    *opts = tpm2_options_new("C:e:G:D:s:P:f:n:p:c:r:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.flags.f && !ctx.ak.out.pub_file) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return tool_rc_option_error;
    }

    if (!ctx.ak.out.ctx_file) {
        LOG_ERR("Expected option -c");
        return tool_rc_option_error;
    }

    bool result = tpm2_util_object_load(ectx, ctx.ek.ctx_arg,
                                &ctx.ek.ek_ctx);
    if (!result) {
        return tool_rc_general_error;
    }

    if (!ctx.ek.ek_ctx.tr_handle) {
        bool res = tpm2_util_sys_handle_to_esys_handle(ectx,
                    ctx.ek.ek_ctx.handle, &ctx.ek.ek_ctx.tr_handle);
        if (!res) {
            LOG_ERR("Converting ek_ctx TPM2_HANDLE to ESYS_TR");
            return tool_rc_general_error;
        }
    }

    result = tpm2_auth_util_from_optarg(NULL, ctx.ek.auth_str,
            &ctx.ek.session, true);
    if (!result) {
        LOG_ERR("Invalid endorse authorization, got\"%s\"",
            ctx.ek.auth_str);
        return tool_rc_general_error;
    }

    tpm2_session *tmp;
    result = tpm2_auth_util_from_optarg(NULL, ctx.ak.auth_str,
            &tmp, true);
    if (!result) {
        LOG_ERR("Invalid AK authorization, got\"%s\"", ctx.ak.auth_str);
        return tool_rc_general_error;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.ak.in.inSensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    return create_ak(ectx);
}
