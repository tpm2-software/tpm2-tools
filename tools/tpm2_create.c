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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_errata.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_create_ctx tpm_create_ctx;
struct tpm_create_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPM2B_SENSITIVE_CREATE in_sensitive;
    TPM2B_PUBLIC in_public;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMI_DH_OBJECT parent_handle;
    char *input;
    char *opu_path;
    char *opr_path;
    char *context_parent_path;
    char *key_auth_str;
    char *parent_auth_str;
    struct {
        UINT16 H : 1;
        UINT16 P : 1;
        UINT16 K : 1;
        UINT16 g : 1;
        UINT16 G : 1;
        UINT16 A : 1;
        UINT16 I : 1;
        UINT16 L : 1;
        UINT16 u : 1;
        UINT16 c : 1;
        UINT16 r : 1;
    } flags;
};

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .objectAttributes = \
                  TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM \
                  |TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN| \
                   TPMA_OBJECT_USERWITHAUTH \
    }, \
}

static tpm_create_ctx ctx = {
    .auth = {
            .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    },
    .type = TPM2_ALG_SHA1,
    .nameAlg = TPM2_ALG_RSA,
    .in_public = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT
};

int setup_alg()
{
    switch(ctx.nameAlg) {
    case TPM2_ALG_SHA1:
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SHA384:
    case TPM2_ALG_SHA512:
    case TPM2_ALG_SM3_256:
    case TPM2_ALG_NULL:
        ctx.in_public.publicArea.nameAlg = ctx.nameAlg;
        break;
    default:
        LOG_ERR("nameAlg algorithm: 0x%0x not support !", ctx.nameAlg);
        return -1;
    }

    switch(ctx.in_public.publicArea.type) {
    case TPM2_ALG_RSA:
        ctx.in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
        ctx.in_public.publicArea.parameters.rsaDetail.exponent = 0;
        ctx.in_public.publicArea.unique.rsa.size = 0;
        break;

    case TPM2_ALG_KEYEDHASH:
        ctx.in_public.publicArea.unique.keyedHash.size = 0;
        ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
        if (ctx.flags.I) {
            // sealing
            ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
            ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
            ctx.in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
        } else {
            // hmac
            ctx.in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
            ctx.in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
            ctx.in_public.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = ctx.nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM2_ALG_ECC:
        ctx.in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        ctx.in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        ctx.in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        ctx.in_public.publicArea.unique.ecc.x.size = 0;
        ctx.in_public.publicArea.unique.ecc.y.size = 0;
        break;

    case TPM2_ALG_SYMCIPHER:
        tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                          &ctx.in_public.publicArea.objectAttributes);

        ctx.in_public.publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
        ctx.in_public.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        ctx.in_public.publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
        ctx.in_public.publicArea.unique.sym.size = 0;
        break;

    default:
        LOG_ERR("type algorithm: 0x%0x not support !", ctx.in_public.publicArea.type);
        return -2;
    }
    return 0;
}

static bool create(TSS2_SYS_CONTEXT *sapi_context) {
    TSS2_RC rval;
    TSS2L_SYS_AUTH_COMMAND sessionsData =
            TSS2L_SYS_AUTH_COMMAND_INIT(1, { ctx.auth.session_data });
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_PRIVATE           outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;


    ctx.in_sensitive.size = ctx.in_sensitive.sensitive.userAuth.size + 2;

    if(setup_alg()) {
        return false;
    }

    creationPCR.count = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, ctx.parent_handle, &sessionsData, &ctx.in_sensitive,
                           &ctx.in_public, &outsideInfo, &creationPCR, &outPrivate,&outPublic,
                           &creationData, &creationHash, &creationTicket, &sessionsDataOut));
    if(rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Create, rval);
        return false;
    }

    tpm2_util_public_to_yaml(&outPublic);

    if (ctx.flags.u) {
        bool res = files_save_public(&outPublic, ctx.opu_path);
        if(!res) {
            return false;
        }
    }

    if (ctx.flags.r) {
        bool res = files_save_private(&outPrivate, ctx.opr_path);
        if (!res) {
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'H':
        if(!tpm2_util_string_to_uint32(value, &ctx.parent_handle)) {
            LOG_ERR("Invalid parent handle, got\"%s\"", value);
            return false;
        }
        ctx.flags.H = 1;
        break;
    case 'P':
        /*
         * since the auth for the parent key may be a session, we need to
         * move this call to tpm2_auth_util_from_optarg to the
         * tpm2_tool_onrun function.
         */
        ctx.flags.P = 1;
        ctx.parent_auth_str = value;
        break;
    case 'K': {
        ctx.flags.K = 1;
        ctx.key_auth_str = value;
    } break;
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value);
        if(ctx.nameAlg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
            return false;
        }
        ctx.flags.g = 1;
        break;
    case 'G':
        ctx.in_public.publicArea.type = tpm2_alg_util_from_optarg(value);
        if(ctx.in_public.publicArea.type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got\"%s\"", value);
            return false;
        }

        ctx.flags.G = 1;
        break;
    case 'A': {
        bool res = tpm2_attr_util_obj_from_optarg(value,
                &ctx.in_public.publicArea.objectAttributes);
        if(!res) {
            LOG_ERR("Invalid object attribute, got\"%s\"", value);
            return false;
        }
        ctx.flags.A = 1;
    } break;
    case 'I':
        ctx.input = strcmp("-", value) ? value : NULL;
        ctx.flags.I = 1;
        break;
    case 'L':
        ctx.in_public.publicArea.authPolicy.size = sizeof(ctx.in_public.publicArea.authPolicy) - 2;
        if(!files_load_bytes_from_path(value, ctx.in_public.publicArea.authPolicy.buffer,
                                       &ctx.in_public.publicArea.authPolicy.size)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'u':
        ctx.opu_path = value;
        if(files_does_file_exist(ctx.opu_path) != 0) {
            return false;
        }
        ctx.flags.u = 1;
        break;
    case 'r':
        ctx.opr_path = value;
        if(files_does_file_exist(ctx.opr_path) != 0) {
            return false;
        }
        ctx.flags.r = 1;
        break;
    case 'c':
        ctx.context_parent_path = value;
        if(ctx.context_parent_path == NULL || ctx.context_parent_path[0] == '\0') {
            return false;
        }
        ctx.flags.c = 1;
        break;
    };

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "parent",               required_argument, NULL, 'H' },
      { "auth-parent",          required_argument, NULL, 'P' },
      { "auth-key",             required_argument, NULL, 'K' },
      { "halg",                 required_argument, NULL, 'g' },
      { "kalg",                 required_argument, NULL, 'G' },
      { "object-attributes",    required_argument, NULL, 'A' },
      { "in-file",              required_argument, NULL, 'I' },
      { "policy-file",          required_argument, NULL, 'L' },
      { "pubfile",              required_argument, NULL, 'u' },
      { "privfile",             required_argument, NULL, 'r' },
      { "context-parent",       required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("H:P:K:g:G:A:I:L:u:r:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

static bool load_sensitive(void) {

    ctx.in_sensitive.sensitive.data.size = BUFFER_SIZE(typeof(ctx.in_sensitive.sensitive.data), buffer);
    return files_load_bytes_from_file_or_stdin(ctx.input,
            &ctx.in_sensitive.sensitive.data.size, ctx.in_sensitive.sensitive.data.buffer);
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    if (ctx.flags.I) {
        bool res = load_sensitive();
        if (!res) {
            goto out;
        }
    }

    if (ctx.flags.I && ctx.in_public.publicArea.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        goto out;
    }

    if(!((ctx.flags.H || ctx.flags.c) && ctx.flags.g && ctx.flags.G)) {
        LOG_ERR("Invalid options");
        goto out;
    }

    if(ctx.flags.c) {
        result = files_load_tpm_context_from_path(sapi_context,
                             &ctx.parent_handle, ctx.context_parent_path);
        if (!result) {
            goto out;
        }
    }

    if (ctx.flags.K) {
        TPMS_AUTH_COMMAND tmp;
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.key_auth_str, &tmp, NULL);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.key_auth_str);
            goto out;
        }
        ctx.in_sensitive.sensitive.userAuth = tmp.hmac;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.parent_auth_str,
            &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
            goto out;
        }
    }

    result = create(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    result = tpm2_session_save (sapi_context, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
