/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"

#define ATTRS  \
    TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_USERWITHAUTH| \
    TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM| \
    TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN

/* Templates from TCG EK Credential Profile TPM 2.0, Version 2.4 Rev. 3, 2021 */

static const TPM2B_DIGEST policy_a_sha384 = {
    .size = 48,
    .buffer = {
        0x8b, 0xbf, 0x22, 0x66, 0x53, 0x7c, 0x17, 0x1c, 0xb5, 0x6e,
        0x40, 0x3c, 0x4d, 0xc1, 0xd4, 0xb6, 0x4f, 0x43, 0x26, 0x11,
        0xdc, 0x38, 0x6e, 0x6f, 0x53, 0x20, 0x50, 0xc3, 0x27, 0x8c,
        0x93, 0x0e, 0x14, 0x3e, 0x8b, 0xb1, 0x13, 0x38, 0x24, 0xcc,
        0xb4, 0x31, 0x05, 0x38, 0x71, 0xc6, 0xdb, 0x53 }
};

static const TPM2B_DIGEST policy_a_sha512 = {
    .size = 64,
    .buffer = {
        0x1e, 0x3b, 0x76, 0x50, 0x2c, 0x8a, 0x14, 0x25, 0xaa, 0x0b,
        0x7b, 0x3f, 0xc6, 0x46, 0xa1, 0xb0, 0xfa, 0xe0, 0x63, 0xb0,
        0x3b, 0x53, 0x68, 0xf9, 0xc4, 0xcd, 0xde, 0xca, 0xff, 0x08,
        0x91, 0xdd, 0x68, 0x2b, 0xac, 0x1a, 0x85, 0xd4, 0xd8, 0x32,
        0xb7, 0x81, 0xea, 0x45, 0x19, 0x15, 0xde, 0x5f, 0xc5, 0xbf,
        0x0d, 0xc4, 0xa1, 0x91, 0x7c, 0xd4, 0x2f, 0xa0, 0x41, 0xe3,
        0xf9, 0x98, 0xe0, 0xee }
};

static const TPM2B_DIGEST policy_a_sm3_256 = {
    .size = 32,
    .buffer = {
        0xc6, 0x7f, 0x7d, 0x35, 0xf6, 0x6f, 0x3b, 0xec, 0x13, 0xc8,
        0x9f, 0xe8, 0x98, 0x92, 0x1c, 0x65, 0x1b, 0x0c, 0xb5, 0xa3,
        0x8a, 0x92, 0x69, 0x0a, 0x62, 0xa4, 0x3c, 0x00, 0x12, 0xe4,
        0xfb, 0x8b }
};

static const TPM2B_DIGEST policy_c_sha384 = {
    .size = 48,
    .buffer = {
        0xd6, 0x03, 0x2c, 0xe6, 0x1f, 0x2f, 0xb3, 0xc2, 0x40, 0xeb,
        0x3c, 0xf6, 0xa3, 0x32, 0x37, 0xef, 0x2b, 0x6a, 0x16, 0xf4,
        0x29, 0x3c, 0x22, 0xb4, 0x55, 0xe2, 0x61, 0xcf, 0xfd, 0x21,
        0x7a, 0xd5, 0xb4, 0x94, 0x7c, 0x2d, 0x73, 0xe6, 0x30, 0x05,
        0xee, 0xd2, 0xdc, 0x2b, 0x35, 0x93, 0xd1, 0x65 }
};

static const TPM2B_DIGEST policy_c_sha512 = {
    .size = 64,
    .buffer = {
        0x58, 0x9e, 0xe1, 0xe1, 0x46, 0x54, 0x47, 0x16, 0xe8, 0xde,
        0xaf, 0xe6, 0xdb, 0x24, 0x7b, 0x01, 0xb8, 0x1e, 0x9f, 0x9c,
        0x7d, 0xd1, 0x6b, 0x81, 0x4a, 0xa1, 0x59, 0x13, 0x87, 0x49,
        0x10, 0x5f, 0xba, 0x53, 0x88, 0xdd, 0x1d, 0xea, 0x70, 0x2f,
        0x35, 0x24, 0x0c, 0x18, 0x49, 0x33, 0x12, 0x1e, 0x2c, 0x61,
        0xb8, 0xf5, 0x0d, 0x3e, 0xf9, 0x13, 0x93, 0xa4, 0x9a, 0x38,
        0xc3, 0xf7, 0x3f, 0xc8 }
};

static const TPM2B_DIGEST policy_c_sm3_256 = {
    .size = 32,
    .buffer = {
        0x2d, 0x4e, 0x81, 0x57, 0x8c, 0x35, 0x31, 0xd9, 0xbd, 0x1c,
        0xdd, 0x7d, 0x02, 0xba, 0x29, 0x8d, 0x56, 0x99, 0xa3, 0xe3,
        0x9f, 0xc3, 0x55, 0x1b, 0xfe, 0xff, 0xcf, 0x13, 0x2b, 0x49,
        0xe1, 0x1d }
};

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
            TPM2B_SENSITIVE_CREATE in_sensitive;
            struct {
                const char *type;
                const char *digest;
                const char *sign;
            } alg;
        } in;
        struct {
            const char *ctx_file;
            tpm2_convert_pubkey_fmt pub_fmt;
            const char *pub_file;
            const char *name_file;
            const char *priv_file;
            const char *qname_file;
        } out;
        char *auth_str;
    } ak;
    struct {
        UINT8 f :1;
    } flags;
    bool autoflush;
};

static createak_context ctx = {
    .ak = {
        .in = {
            .alg = {
                .type = "rsa2048",
                .digest = "sha256",
                .sign = "null"
            },
        },
        .out = {
            .pub_fmt = pubkey_format_tss
        },
    },
    .flags = { 0 },
    .autoflush = false
};

static tool_rc init_ak_public(TPMI_ALG_HASH name_alg, TPM2B_PUBLIC *public) {

    const char *name_halg;
    char alg[256];

    name_halg = tpm2_alg_util_algtostr(name_alg, tpm2_alg_util_flags_hash);

    if (!strcmp(ctx.ak.in.alg.sign, "null")) {
        if (!strncmp(ctx.ak.in.alg.type, "rsa", 3)) {
            ctx.ak.in.alg.sign = "rsassa";
        } else if (!strncmp(ctx.ak.in.alg.type, "ecc", 3)) {
            ctx.ak.in.alg.sign = "ecdsa";
        }
    }
    if (!strcmp(ctx.ak.in.alg.type, "keyedhash"))
    {
        ctx.ak.in.alg.type = "hmac";
    }
    if (!strcmp(ctx.ak.in.alg.type, "hmac"))
    {
        snprintf(alg, sizeof(alg), "%s:%s", ctx.ak.in.alg.type,
            ctx.ak.in.alg.digest);

    } else {
        snprintf(alg, sizeof(alg), "%s:%s-%s:null", ctx.ak.in.alg.type,
        ctx.ak.in.alg.sign, ctx.ak.in.alg.digest);
    }
    return tpm2_alg_util_public_init(alg, name_halg, NULL, NULL, ATTRS, public);
}

static tool_rc create_ak(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_general_error;

    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    TPM2B_DATA outside_info = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *out_public;
    TPM2B_PRIVATE *out_private;
    TPM2B_PUBLIC in_public;
    TPML_DIGEST pHashList = { .count = 2 };

    /* get the nameAlg of the EK */
    TPM2_ALG_ID ek_name_alg = tpm2_alg_util_get_name_alg(ectx, ctx.ek.ek_ctx.tr_handle);
    if (ek_name_alg == TPM2_ALG_ERROR) {
        return tool_rc_general_error;
    }

    /* select the matching EK templates */
    switch (ek_name_alg) {
    case TPM2_ALG_SHA384:
        pHashList.digests[0] = policy_a_sha384;
        pHashList.digests[1] = policy_c_sha384;
        break;
    case TPM2_ALG_SHA512:
        pHashList.digests[0] = policy_a_sha512;
        pHashList.digests[1] = policy_c_sha512;
        break;
    case TPM2_ALG_SM3_256:
        pHashList.digests[0] = policy_a_sm3_256;
        pHashList.digests[1] = policy_c_sm3_256;
        break;
    case TPM2_ALG_SHA256:
    default:
        pHashList.count = 0;
        break;
    }

    tool_rc tmp_rc = init_ak_public(ek_name_alg, &in_public);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }

    tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }
    tpm2_session_set_authhash(data, ek_name_alg);

    tpm2_session *session = NULL;
    tmp_rc = tpm2_session_open(ectx, data, &session);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Could not start tpm session");
        return tmp_rc;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    ESYS_TR sess_handle = tpm2_session_get_handle(session);

    ESYS_TR shandle = ESYS_TR_NONE;
    tmp_rc = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_ENDORSEMENT,
            ctx.ek.session, &shandle);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
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

    if (pHashList.count > 1) {
        rval = Esys_PolicyOR(ectx, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pHashList);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PolicyOR, rval);
            goto out_session;
        }
    }

    TPM2B_CREATION_DATA *creation_data = NULL;
    rval = Esys_Create(ectx, ctx.ek.ek_ctx.tr_handle, sess_handle, ESYS_TR_NONE,
            ESYS_TR_NONE, &ctx.ak.in.in_sensitive, &in_public, &outside_info,
            &creation_pcr, &out_private, &out_public, &creation_data, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Create, rval);
        goto out;
    }
    LOG_INFO("Esys_Create success");

    rc = tpm2_session_close(&session);
    if (rc != tool_rc_success) {
        goto out;
    }

    data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        goto out;
    }
    tpm2_session_set_authhash(data, ek_name_alg);

    tmp_rc = tpm2_session_open(ectx, data, &session);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Could not start tpm session");
        rc = tmp_rc;
        goto out;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    sess_handle = tpm2_session_get_handle(session);

    tmp_rc = tpm2_auth_util_get_shandle(ectx, sess_handle, ctx.ek.session,
            &shandle);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out;
    }

    rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle, shandle,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        goto out;
    }
    LOG_INFO("Esys_PolicySecret success");

    if (pHashList.count > 1) {
        rval = Esys_PolicyOR(ectx, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pHashList);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PolicyOR, rval);
            goto out;
        }
    }

    ESYS_TR loaded_sha1_key_handle;
    rval = Esys_Load(ectx, ctx.ek.ek_ctx.tr_handle, sess_handle, ESYS_TR_NONE,
            ESYS_TR_NONE, out_private, out_public, &loaded_sha1_key_handle);
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

    rc = tpm2_session_close(&session);
    if (rc != tool_rc_success) {
        goto out;
    }

    /* generation qualified name */
    TPM2B_NAME *p_qname = &creation_data->creationData.parentQualifiedName;
    TPM2B_NAME qname = { 0 };
    rc = tpm2_calq_qname(p_qname,
            in_public.publicArea.nameAlg, key_name, &qname) ?
                    tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        goto out;
    }

    /* Output in YAML format */
    tpm2_tool_output("loaded-key:\n  name: ");
    tpm2_util_print_tpm2b(key_name);
    tpm2_tool_output("\n");
    tpm2_tool_output("  qualified name: ");
    tpm2_util_print_tpm2b(&qname);
    tpm2_tool_output("\n");

    // write name to ak.name file
    if (ctx.ak.out.name_file) {
        if (!files_save_bytes_to_file(ctx.ak.out.name_file, key_name->name,
                key_name->size)) {
             LOG_ERR("Failed to save AK name into file \"%s\"",
                    ctx.ak.out.name_file);
            goto nameout;
        }
    }

    if (ctx.ak.out.qname_file) {
        if (!files_save_bytes_to_file(ctx.ak.out.qname_file, qname.name,
                qname.size)) {
            LOG_ERR("Failed to save AK qualified name into file \"%s\"",
                    ctx.ak.out.name_file);
            goto nameout;
        }
    }

    // If the AK isn't persisted we always save a context file of the
    // transient AK handle for future tool interactions.
    tmp_rc = files_save_tpm_context_to_path(ectx, loaded_sha1_key_handle,
             ctx.ak.out.ctx_file, false);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        LOG_ERR("Error saving tpm context for handle");
        goto nameout;
    }

    if (ctx.ak.out.pub_file) {
        if (!tpm2_convert_pubkey_save(out_public, ctx.ak.out.pub_fmt,
                ctx.ak.out.pub_file)) {
            goto nameout;
        }
    }

    if (ctx.ak.out.priv_file) {
        if (!files_save_private(out_private, ctx.ak.out.priv_file)) {
            goto nameout;
        }
    }

    rc = tool_rc_success;

nameout:
    free(key_name);
out:
    free(out_public);
    free(out_private);
    Esys_Free(creation_data);
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
        ctx.ak.in.alg.type = tpm2_alg_util_numtoalgstr(value,
                                 tpm2_alg_util_flags_base);
        if (!ctx.ak.in.alg.type) {
            LOG_ERR("Could not convert key algorithm, got \"%s\"", value);
            return false;
        }
        break;
    case 'g':
        ctx.ak.in.alg.digest = tpm2_alg_util_numtoalgstr(value,
                                tpm2_alg_util_flags_hash);
        if (!ctx.ak.in.alg.digest) {
            LOG_ERR("Could not convert digest algorithm, got \"%s\"", value);
            return false;
        }
        break;
    case 's':
         ctx.ak.in.alg.sign = tpm2_alg_util_numtoalgstr(value,
                                tpm2_alg_util_flags_sig);
        if (!ctx.ak.in.alg.sign) {
            LOG_ERR("Could not convert signing algorithm, got \"%s\"", value);
            return false;
        }
        break;
    case 'P':
        ctx.ek.auth_str = value;
        break;
    case 'p':
        ctx.ak.auth_str = value;
        break;
    case 'u':
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
    case 'q':
        ctx.ak.out.qname_file = value;
        break;
    case 'R':
        ctx.autoflush = true;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "eh-auth",           required_argument, NULL, 'P' },
        { "ak-auth",           required_argument, NULL, 'p' },
        { "ek-context",        required_argument, NULL, 'C' },
        { "ak-context",        required_argument, NULL, 'c' },
        { "ak-name",           required_argument, NULL, 'n' },
        { "key-algorithm",     required_argument, NULL, 'G' },
        { "hash-algorithm",    required_argument, NULL, 'g' },
        { "signing-algorithm", required_argument, NULL, 's' },
        { "format",            required_argument, NULL, 'f' },
        { "public",            required_argument, NULL, 'u' },
        { "private",           required_argument, NULL, 'r' },
        { "ak-qualified-name", required_argument, NULL, 'q' },
        { "autoflush",         no_argument,       NULL, 'R' },
    };

    *opts = tpm2_options_new("P:p:C:c:n:G:g:s:f:u:r:q:R", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.flags.f && !ctx.ak.out.pub_file) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return tool_rc_option_error;
    }

    if (!ctx.ak.out.ctx_file) {
        LOG_ERR("Expected option -c");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load(ectx, ctx.ek.ctx_arg, &ctx.ek.ek_ctx,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (!ctx.ek.ek_ctx.tr_handle) {
        rc = tpm2_util_sys_handle_to_esys_handle(ectx, ctx.ek.ek_ctx.handle,
                &ctx.ek.ek_ctx.tr_handle);
        if (rc != tool_rc_success) {
            LOG_ERR("Converting ek_ctx TPM2_HANDLE to ESYS_TR");
            return rc;
        }
    }

    rc = tpm2_auth_util_from_optarg(NULL, ctx.ek.auth_str, &ctx.ek.session,
            true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid endorse authorization");
        return rc;
    }

    tpm2_session *tmp;
    rc = tpm2_auth_util_from_optarg(NULL, ctx.ak.auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid AK authorization");
        return rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.ak.in.in_sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    return create_ak(ectx);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("createak", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
