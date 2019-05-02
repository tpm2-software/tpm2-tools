/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_convert.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_hierarchy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_capability.h"
#include "tpm2_nv_util.h"

#define RSA_EK_NONCE_NV_INDEX 0x01c00003
#define RSA_EK_TEMPLATE_NV_INDEX 0x01c00004
#define ECC_EK_NONCE_NV_INDEX 0x01c0000b
#define ECC_EK_TEMPLATE_NV_INDEX 0x01c0000c

typedef struct createek_context createek_context;
struct createek_context {
    struct {
        struct {
            TPMS_AUTH_COMMAND session_data;
            tpm2_session *session;
        } owner;
        struct {
            TPMS_AUTH_COMMAND session_data;
            tpm2_session *session;
        } endorse;
        struct {
            TPMS_AUTH_COMMAND session_data;
            tpm2_session *session;
        } ek;
    } auth;
    tpm2_hierarchy_pdata objdata;
    char *out_file_path;
    tpm2_convert_pubkey_fmt format;
    struct {
        UINT8 f : 1;
        UINT8 e : 1;
        UINT8 w : 1;
        UINT8 P : 1;
        UINT8 t : 1;
        UINT8 unused : 3;
    } flags;
    char *endorse_auth_str;
    char *owner_auth_str;
    char *ek_auth_str;
    bool find_persistent_handle;
    const char *context_arg;
    tpm2_loaded_object ctx_obj;
};

static createek_context ctx = {
    .auth = {
        .owner =   { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        .endorse = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
        .ek =      { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    },
    .format = pubkey_format_tss,
    .objdata = TPM2_HIERARCHY_DATA_INIT,
    .flags = { 0 },
    .find_persistent_handle = false
};

static bool set_key_algorithm(TPM2B_PUBLIC *inPublic)
{

    switch (inPublic->publicArea.type) {
    case TPM2_ALG_RSA :
        inPublic->publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_AES;
        inPublic->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPublic->publicArea.parameters.rsaDetail.symmetric.mode.aes =
                TPM2_ALG_CFB;
        inPublic->publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_NULL;
        inPublic->publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->publicArea.unique.rsa.size = 256;
        break;
    case TPM2_ALG_KEYEDHASH :
        inPublic->publicArea.parameters.keyedHashDetail.scheme.scheme =
                TPM2_ALG_XOR;
        inPublic->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg =
                TPM2_ALG_SHA256;
        inPublic->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf =
                TPM2_ALG_KDF1_SP800_108;
        inPublic->publicArea.unique.keyedHash.size = 0;
        break;
    case TPM2_ALG_ECC :
        inPublic->publicArea.parameters.eccDetail.symmetric.algorithm =
                TPM2_ALG_AES;
        inPublic->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        inPublic->publicArea.parameters.eccDetail.symmetric.mode.sym =
                TPM2_ALG_CFB;
        inPublic->publicArea.parameters.eccDetail.scheme.scheme =
                TPM2_ALG_NULL;
        inPublic->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        inPublic->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        inPublic->publicArea.unique.ecc.x.size = 32;
        inPublic->publicArea.unique.ecc.y.size = 32;
        break;
    case TPM2_ALG_SYMCIPHER :
        inPublic->publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
        inPublic->publicArea.parameters.symDetail.sym.keyBits.aes = 128;
        inPublic->publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
        inPublic->publicArea.unique.sym.size = 0;
        break;
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", inPublic->publicArea.type);
        return false;
    }

    return true;
}

static bool set_ek_template(ESYS_CONTEXT *ectx, TPM2B_PUBLIC *inPublic) {
    TPM2_HANDLE template_nv_index;
    TPM2_HANDLE nonce_nv_index;

    switch (inPublic->publicArea.type) {
    case TPM2_ALG_RSA :
        template_nv_index = RSA_EK_TEMPLATE_NV_INDEX;
        nonce_nv_index = RSA_EK_NONCE_NV_INDEX;
        break;
    case TPM2_ALG_ECC :
        template_nv_index = ECC_EK_TEMPLATE_NV_INDEX;
        nonce_nv_index = ECC_EK_NONCE_NV_INDEX;
        break;
    default:
        LOG_ERR("EK template and EK nonce for algorithm type input(%4.4x)"
                " are not supported!", inPublic->publicArea.type);
        return false;
    }

    UINT8* template = NULL;
    UINT8* nonce = NULL;

    // Read EK template
    UINT16 template_size;
    bool result = tpm2_util_nv_read(ectx, template_nv_index, 0, 0, TPM2_RH_OWNER,
                                    &ctx.auth.endorse.session_data, ctx.auth.endorse.session,
                                    &template, &template_size);
    if (!result) {
        result = false;
        goto out;
    }

    TSS2_RC ret = Tss2_MU_TPMT_PUBLIC_Unmarshal(template, template_size,
                                                NULL, &inPublic->publicArea);
    if (ret != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to unmarshal TPMT_PUBLIC from buffer 0x%p", template);
        result = false;
        goto out;
    }

    // Read EK nonce
    UINT16 nonce_size;
    result = tpm2_util_nv_read(ectx, nonce_nv_index, 0, 0, TPM2_RH_OWNER,
                               &ctx.auth.endorse.session_data, ctx.auth.endorse.session,
                               &nonce, &nonce_size);
    if (!result) {
        // EK template populated / ek nonce unpopulated is a valid state. Just return
        result = true;
        goto out;
    }

    if (inPublic->publicArea.type == TPM2_ALG_RSA) {
        memcpy(&inPublic->publicArea.unique.rsa.buffer, &nonce, nonce_size);
        inPublic->publicArea.unique.rsa.size = 256;
    } else {
        // ECC is only other supported algorithm
        memcpy(&inPublic->publicArea.unique.ecc.x.buffer, &nonce, nonce_size);
        inPublic->publicArea.unique.ecc.x.size = 32;
        inPublic->publicArea.unique.ecc.y.size = 32;
    }

out:
    if (template) {
        free(template);
    }

    if (nonce) {
        free(nonce);
    }

    return result;
}

static bool create_ek_handle(ESYS_CONTEXT *ectx) {
    bool result;

    if (ctx.flags.t) {
        result = set_ek_template(ectx, &ctx.objdata.in.public);
        if (!result) {
            return false;
        }
    } else {
        result = set_key_algorithm(&ctx.objdata.in.public);
        if (!result) {
            return false;
        }
    }

    result = tpm2_hierarchy_create_primary(ectx, &ctx.auth.endorse.session_data,
            ctx.auth.endorse.session, &ctx.objdata);
    if (!result) {
        return false;
    }

    if (ctx.ctx_obj.handle) {

        result = tpm2_ctx_mgmt_evictcontrol(ectx, ESYS_TR_RH_OWNER,
                &ctx.auth.owner.session_data, ctx.auth.owner.session,
                ctx.objdata.out.handle,
                ctx.ctx_obj.handle);
        if (!result) {
            return false;
        }

        TSS2_RC rval = Esys_FlushContext(ectx, ctx.objdata.out.handle);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Esys_FlushContext, rval);
            return false;
        }
    } else {
        /* If it wasn't persistent, save a context for future tool interactions */
        char *filename = NULL;

        if (!ctx.ctx_obj.path) {
            /* Ensure the context file path is unique, we don't want to clobber
            * existing files.
            */
            bool ok = files_get_unique_name("ek.ctx", &filename);
            if (!ok) {
                return false;
            }
        } else {
            /* Make a copy of specified path so we can free properly below */
            filename = strdup(ctx.ctx_obj.path);
            if (!filename) {
                LOG_ERR("oom");
                return false;
            }
        }

        bool result = files_save_tpm_context_to_path(ectx,
                ctx.objdata.out.handle, filename);
        if (!result) {
            LOG_ERR("Error saving tpm context for handle");
            free(filename);
            return false;
        }
        tpm2_tool_output("transient-object-context: %s\n", filename);
        free(filename);
    }

    if (ctx.out_file_path) {
        bool ok = tpm2_convert_pubkey_save(ctx.objdata.out.public,
                ctx.format, ctx.out_file_path);
        if (!ok) {
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'e':
        ctx.flags.e = 1;
        ctx.endorse_auth_str = value;
        break;
    case 'w':
        ctx.flags.w = 1;
        ctx.owner_auth_str = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.ek_auth_str = value;
        break;
    case 'G': {
        TPMI_ALG_PUBLIC type = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_base);
        if (type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got \"%s\"", value);
            return false;
        }
        ctx.objdata.in.public.publicArea.type = type;
    }   break;
    case 'p':
        if (!value) {
            LOG_ERR("Please specify an output file to save the pub ek to.");
            return false;
        }
        ctx.out_file_path = value;
        break;
    case 'f':
        ctx.format = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = true;
        break;
    case 'c':
        ctx.context_arg = value;
        break;
    case 't':
        ctx.flags.t = true;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-endorse",         required_argument, NULL, 'e' },
        { "auth-owner",           required_argument, NULL, 'w' },
        { "auth-ek",              required_argument, NULL, 'P' },
        { "algorithm",            required_argument, NULL, 'G' },
        { "file",                 required_argument, NULL, 'p' },
        { "format",               required_argument, NULL, 'f' },
        { "context",              required_argument, NULL, 'c' },
        { "template",             required_argument, NULL, 't' },
    };

    *opts = tpm2_options_new("e:w:P:G:p:f:c:t", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static void set_default_obj_attrs(void) {

    ctx.objdata.in.public.publicArea.objectAttributes =
      TPMA_OBJECT_RESTRICTED  | TPMA_OBJECT_ADMINWITHPOLICY
    | TPMA_OBJECT_DECRYPT     | TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
}

static void set_default_auth_policy(void) {

    static const TPM2B_DIGEST auth_policy = {
        .size = 32,
        .buffer = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
        }
    };

    TPM2B_DIGEST *authp = &ctx.objdata.in.public.publicArea.authPolicy;
    *authp = auth_policy;
}

static void set_default_hierarchy(void) {
    ctx.objdata.in.hierarchy = TPM2_RH_ENDORSEMENT;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    size_t i;
    int rc = 1;

    tpm2_session **sessions[] = {
       &ctx.auth.ek.session,
       &ctx.auth.endorse.session,
       &ctx.auth.owner.session,
    };

    if (ctx.flags.f && !ctx.out_file_path) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return -1;
    }

    bool ret;
    if (ctx.context_arg && !strcmp(ctx.context_arg, "-")) {
        /* If user passes a handle of '-' we try and find a vacant slot for
         * to use and tell them what it is.
         */
        ret = tpm2_capability_find_vacant_persistent_handle(ectx,
                        &ctx.ctx_obj.handle);
        if (!ret) {
            LOG_ERR("handle/-H passed with a value '-' but unable to find a"
                    " vacant persistent handle!");
            goto out;
        }
        tpm2_tool_output("persistent-handle: 0x%x\n", ctx.ctx_obj.handle);
    } else if (ctx.context_arg) {
        ret = tpm2_util_string_to_uint32(ctx.context_arg,
                        &ctx.ctx_obj.handle);
        if (!ret) {
            goto out;
        }
    }

    if (ctx.flags.e) {
        bool res = tpm2_auth_util_from_optarg(ectx, ctx.endorse_auth_str,
                &ctx.auth.endorse.session_data, &ctx.auth.endorse.session);
        if (!res) {
            LOG_ERR("Invalid endorse authorization, got\"%s\"",
                ctx.endorse_auth_str);
            return 1;
        }
    }
    if (ctx.flags.w) {
        bool res = tpm2_auth_util_from_optarg(ectx, ctx.owner_auth_str,
                &ctx.auth.owner.session_data, &ctx.auth.owner.session);
        if (!res) {
            LOG_ERR("Invalid owner authorization, got\"%s\"", ctx.owner_auth_str);
            return 1;
        }
    }
    if (ctx.flags.P) {
        bool res = tpm2_auth_util_from_optarg(ectx, ctx.ek_auth_str,
                &ctx.auth.ek.session_data, &ctx.auth.ek.session);
        if (!res) {
            LOG_ERR("Invalid EK authorization, got\"%s\"", ctx.ek_auth_str);
            return 1;
        }
    }

    /* override the default attrs */
    set_default_obj_attrs();

    /* set the auth policy */
    set_default_auth_policy();

    /* set the default hierarchy */
    set_default_hierarchy();

    /* normalize 0 success 1 failure */
    bool result = create_ek_handle(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    for(i=0; i < ARRAY_LEN(sessions); i++) {
        tpm2_session *s = *sessions[i];
        result = tpm2_session_save (ectx, s, NULL);
        if (!result) {
            rc = 1;
        }
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session **sessions[] = {
       &ctx.auth.ek.session,
       &ctx.auth.endorse.session,
       &ctx.auth.owner.session,
    };

    size_t i;
    for(i=0; i < ARRAY_LEN(sessions); i++) {
        tpm2_session **s = sessions[i];
        tpm2_session_free(s);
    }

    tpm2_hierarchy_pdata_free(&ctx.objdata);
}
