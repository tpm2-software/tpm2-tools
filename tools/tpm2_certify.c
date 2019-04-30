/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_convert.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_certify_ctx tpm_certify_ctx;
struct tpm_certify_ctx {
    TPMI_ALG_HASH  halg;

    struct {
        char *attest;
        char *sig;
    } file_path;

    struct {
        UINT16 g : 1;
        UINT16 o : 1;
        UINT16 s : 1;
        UINT16 f : 1;
    } flags;

    struct {
        char *auth_str;
        tpm2_session *session;
        const char *context_arg;
        tpm2_loaded_object object;
    } object;

    struct {
        char *auth_str;
        tpm2_session *session;
        const char *context_arg;
        tpm2_loaded_object object;
    } key;

    tpm2_convert_sig_fmt sig_fmt;
};

static tpm_certify_ctx ctx = {
    .sig_fmt = signature_format_tss,
};

static bool get_key_type(ESYS_CONTEXT *ectx, ESYS_TR object_handle,
                            TPMI_ALG_PUBLIC *type) {

    TSS2_RC rval;
    bool ret = true;
    TPM2B_PUBLIC *out_public;
    TPM2B_NAME *name;
    TPM2B_NAME *qualified_name;

    rval = Esys_ReadPublic(ectx, object_handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                &out_public, &name, &qualified_name);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ReadPublic, rval);
        *type = TPM2_ALG_ERROR;
        ret = false;
        goto out;
    }

    *type = out_public->publicArea.type;

out:
    free(out_public);
    free(name);
    free(qualified_name);

    return ret;
}

static bool set_scheme(ESYS_CONTEXT *ectx, ESYS_TR key_handle,
        TPMI_ALG_HASH halg, TPMT_SIG_SCHEME *scheme) {

    TPM2_ALG_ID type;
    bool result = get_key_type(ectx, key_handle, &type);
    if (!result) {
        return false;
    }

    switch (type) {
    case TPM2_ALG_RSA :
        scheme->scheme = TPM2_ALG_RSASSA;
        scheme->details.rsassa.hashAlg = halg;
        break;
    case TPM2_ALG_KEYEDHASH :
        scheme->scheme = TPM2_ALG_HMAC;
        scheme->details.hmac.hashAlg = halg;
        break;
    case TPM2_ALG_ECC :
        scheme->scheme = TPM2_ALG_ECDSA;
        scheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM2_ALG_SYMCIPHER :
    default:
        LOG_ERR("Unknown key type, got: 0x%x", type);
        return false;
    }

    return true;
}

static bool certify_and_save_data(ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    TPM2B_DATA qualifying_data = {
        .size = 4,
        .buffer = { 0x00, 0xff, 0x55,0xaa }
    };

    TPMT_SIG_SCHEME scheme;
    bool result = set_scheme(ectx, ctx.key.object.tr_handle, ctx.halg,
                    &scheme);
    if (!result) {
        LOG_ERR("No suitable signing scheme!");
        return false;
    }

    TPM2B_ATTEST *certify_info;
    TPMT_SIGNATURE *signature;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, 
                            ctx.object.object.tr_handle,
                            ctx.object.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get session handle for TPM object");
        return false;
    }

    ESYS_TR shandle2 = tpm2_auth_util_get_shandle(ectx,
                            ctx.key.object.tr_handle,
                            ctx.key.session);
    if (shandle2 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get session handle for key");
        return false;
    }

    rval = Esys_Certify(ectx, ctx.object.object.tr_handle,
                        ctx.key.object.tr_handle,
                        shandle1, shandle2, ESYS_TR_NONE,
                        &qualifying_data, &scheme, &certify_info,
                        &signature);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Eys_Certify, rval);
        return false;
    }

    /* serialization is safe here, since it's just a byte array */
    result = files_save_bytes_to_file(ctx.file_path.attest,
            certify_info->attestationData, certify_info->size);
    if (!result) {
        goto out;
    }

    result = tpm2_convert_sig_save(signature, ctx.sig_fmt, ctx.file_path.sig);

out:
    free(certify_info);
    free(signature);

    return result;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.object.context_arg = value;
        break;
    case 'c':
        ctx.key.context_arg = value;
        break;
    case 'P':
        ctx.object.auth_str = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
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
    case 'f':
        ctx.flags.f = 1;
        ctx.sig_fmt = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_fmt == signature_format_err) {
            return false;
        }
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth-object",      required_argument, NULL, 'P' },
      { "auth-key",         required_argument, NULL, 'p' },
      { "halg",             required_argument, NULL, 'g' },
      { "out-attest-file",  required_argument, NULL, 'o' },
      { "sig-file",         required_argument, NULL, 's' },
      { "obj-context",      required_argument, NULL, 'C' },
      { "key-context",      required_argument, NULL, 'c' },
      { "format",           required_argument, NULL, 'f' },
    };

    *opts = tpm2_options_new("P:p:g:o:s:c:C:f:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    int rc = 1;
    bool result;

    if ((!ctx.object.context_arg)
        && (!ctx.key.context_arg)
        && (ctx.flags.g) && (ctx.flags.o)
        && (ctx.flags.s)) {
        return -1;
    }

    /* Load input files */
    result = tpm2_util_object_load(ectx, ctx.object.context_arg,
                                    &ctx.object.object);
    if (!result) {
        tpm2_tool_output("Failed to load context object (handle: 0x%x, path: %s).\n",
                ctx.object.object.handle, ctx.object.object.path);
        goto out;
    }

    result = tpm2_util_object_load(ectx, ctx.key.context_arg,
            &ctx.key.object);
    if (!result) {
        tpm2_tool_output("Failed to load context object for key (handle: 0x%x, path: %s).\n",
                ctx.key.object.handle, ctx.key.object.path);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.object.auth_str,
            &ctx.object.session, false);
    if (!result) {
        LOG_ERR("Invalid object key authorization, got\"%s\"", ctx.object.auth_str);
        goto out;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.key.auth_str,
            &ctx.key.session, false);
    if (!result) {
        LOG_ERR("Invalid key handle authorization, got\"%s\"", ctx.key.auth_str);
        goto out;
    }

    result = certify_and_save_data(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_session_save(ectx, ctx.key.session, NULL);
    result &= tpm2_session_save(ectx, ctx.object.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.object.session);
    tpm2_session_free(&ctx.key.session);
}
