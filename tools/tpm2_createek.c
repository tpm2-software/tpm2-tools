//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <tss2/tss2_sys.h>

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
    char *context_file;
    TPMI_DH_PERSISTENT persistent_handle;
    tpm2_convert_pubkey_fmt format;
    struct {
        UINT8 f : 1;
        UINT8 e : 1;
        UINT8 o : 1;
        UINT8 P : 1;
        UINT8 unused : 4;
    } flags;
    char *endorse_auth_str;
    char *owner_auth_str;
    char *ek_auth_str;
    bool find_persistent_handle;
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

static bool create_ek_handle(TSS2_SYS_CONTEXT *sapi_context) {

    bool result = set_key_algorithm(&ctx.objdata.in.public);
    if (!result) {
        return false;
    }

    result = tpm2_hierarchy_create_primary(sapi_context, &ctx.auth.endorse.session_data,
            &ctx.objdata);
    if (!result) {
        return false;
    }

    if (ctx.persistent_handle) {

        result = tpm2_ctx_mgmt_evictcontrol(sapi_context, TPM2_RH_OWNER,
                &ctx.auth.owner.session_data, ctx.objdata.out.handle,
                ctx.persistent_handle);
        if (!result) {
            return false;
        }

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx.objdata.out.handle));
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_FlushContext, rval);
            return false;
        }
    } else if (ctx.context_file) {
        bool result = files_save_tpm_context_to_path(sapi_context,
                ctx.objdata.out.handle, ctx.context_file);
        if (!result) {
            LOG_ERR("Error saving tpm context for handle");
            return false;
        }
    }

    /* If it wasn't persistent, output the transient handle */
    if (!ctx.persistent_handle) {
        tpm2_tool_output("0x%X\n", ctx.objdata.out.handle);
    }

    if (ctx.out_file_path) {
        return tpm2_convert_pubkey_save(&ctx.objdata.out.public,
                ctx.format, ctx.out_file_path);
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'H':
        /* If user passes a handle of '-' we try and find a vacant slot for
         * to use and tell them what it is.
         */
        if (!strcmp(value, "-")) {
            ctx.find_persistent_handle = true;
        } else {
            result = tpm2_util_string_to_uint32(value, &ctx.persistent_handle);
            if (!result) {
                LOG_ERR("Could not convert EK persistent from hex format.");
                return false;
            }
        }
        break;
    case 'e':
        ctx.flags.e = 1;
        ctx.endorse_auth_str = value;
        break;
    case 'o':
        ctx.flags.o = 1;
        ctx.owner_auth_str = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.ek_auth_str = value;
        break;
    case 'g': {
        TPMI_ALG_PUBLIC type = tpm2_alg_util_from_optarg(value);
        if (type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got\"%s\"", value);
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
        ctx.context_file = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-endorse",         required_argument, NULL, 'e' },
        { "auth-owner",           required_argument, NULL, 'o' },
        { "auth-ek",              required_argument, NULL, 'P' },
        { "handle",               required_argument, NULL, 'H' },
        { "algorithm",            required_argument, NULL, 'g' },
        { "file",                 required_argument, NULL, 'p' },
        { "format",               required_argument, NULL, 'f' },
        { "context",              required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("e:o:H:P:g:p:f:c:", ARRAY_LEN(topts), topts,
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

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

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
        goto out;
    }

    if (ctx.find_persistent_handle) {
        bool ret = tpm2_capability_find_vacant_persistent_handle(sapi_context,
                        &ctx.persistent_handle);
        if (!ret) {
            LOG_ERR("handle/-H passed with a value '-' but unable to find a"
                    " vacant persistent handle!");
            return 1;
        }
        tpm2_tool_output("persistent-handle: 0x%x\n", ctx.persistent_handle);
    }

    if (ctx.context_file && ctx.persistent_handle) {
        LOG_ERR("Specify either a handle to make it persistent or a file to"
                " save the context to, not both!");
        goto out;
    }

    if (ctx.flags.e) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.endorse_auth_str,
                &ctx.auth.endorse.session_data, &ctx.auth.endorse.session);
        if (!res) {
            LOG_ERR("Invalid endorse authorization, got\"%s\"",
                ctx.endorse_auth_str);
            return 1;
        }
    }
    if (ctx.flags.o) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.owner_auth_str,
                &ctx.auth.owner.session_data, &ctx.auth.owner.session);
        if (!res) {
            LOG_ERR("Invalid owner authorization, got\"%s\"", ctx.owner_auth_str);
            return 1;
        }
    }
    if (ctx.flags.P) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.ek_auth_str,
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
    bool result = create_ek_handle(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    for(i=0; i < ARRAY_LEN(sessions); i++) {
        tpm2_session *s = *sessions[i];
        result = tpm2_session_save (sapi_context, s, NULL);
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
}
