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
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPM2B_SENSITIVE_CREATE sensitive;
    TPM2B_PUBLIC public;
    TPMI_ALG_HASH halg;
    TPMI_RH_HIERARCHY hierarchy;
    char *context_file;
    TPM2_HANDLE handle;
    struct {
        UINT8 H :1;
        UINT8 g :1;
        UINT8 G :1;
    } flags;
};

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .type = TPM2_ALG_RSA, \
        .objectAttributes = \
            TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
            |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
            |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH \
    }, \
}

static tpm_createprimary_ctx ctx = {
    .session_data = {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
        },
    .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
    .public = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT,
    .halg = TPM2_ALG_SHA1,
    .hierarchy = TPM2_RH_NULL
};

static bool setup_alg(TPMI_ALG_HASH halg, TPM2B_PUBLIC *public) {

    switch(halg) {
    case TPM2_ALG_SHA1:
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SHA384:
    case TPM2_ALG_SHA512:
    case TPM2_ALG_SM3_256:
    case TPM2_ALG_NULL:
        public->publicArea.nameAlg = halg;
        break;
    default:
        LOG_ERR("name algorithm \"%s\" not supported!",
                tpm2_alg_util_algtostr(halg));
        return false;
    }

    switch(public->publicArea.type) {
    case TPM2_ALG_RSA: {
        TPMS_RSA_PARMS *r = &public->publicArea.parameters.rsaDetail;
       r->symmetric.algorithm = TPM2_ALG_AES;
       r->symmetric.keyBits.aes = 128;
       r->symmetric.mode.aes = TPM2_ALG_CFB;
       r->scheme.scheme = TPM2_ALG_NULL;
       r->keyBits = 2048;
       r->exponent = 0;
       public->publicArea.unique.rsa.size = 0;
    } break;
    case TPM2_ALG_KEYEDHASH: {
        TPMT_KEYEDHASH_SCHEME *s = &public->publicArea.parameters.keyedHashDetail.scheme;
       s->scheme = TPM2_ALG_XOR;
       s->details.exclusiveOr.hashAlg = TPM2_ALG_SHA256;
       s->details.exclusiveOr.kdf = TPM2_ALG_KDF1_SP800_108;
       public->publicArea.unique.keyedHash.size = 0;
    } break;
    case TPM2_ALG_ECC: {
        TPMS_ECC_PARMS *e = &public->publicArea.parameters.eccDetail;
       e->symmetric.algorithm = TPM2_ALG_AES;
       e->symmetric.keyBits.aes = 128;
       e->symmetric.mode.sym = TPM2_ALG_CFB;
       e->scheme.scheme = TPM2_ALG_NULL;
       e->curveID = TPM2_ECC_NIST_P256;
       e->kdf.scheme = TPM2_ALG_NULL;
       public->publicArea.unique.ecc.x.size = 0;
       public->publicArea.unique.ecc.y.size = 0;
    } break;
    case TPM2_ALG_SYMCIPHER: {
        TPMS_SYMCIPHER_PARMS *s = &public->publicArea.parameters.symDetail;
       s->sym.algorithm = TPM2_ALG_AES;
       s->sym.keyBits.sym = 128;
       s->sym.mode.sym = TPM2_ALG_CFB;
       public->publicArea.unique.sym.size = 0;
    } break;
    default:
        LOG_ERR("type algorithm \"%s\" not supported!",
                tpm2_alg_util_algtostr(public->publicArea.type));

        return false;
    }

    return true;
}

static bool create_primary(TSS2_SYS_CONTEXT *sapi_context) {

    bool res = setup_alg(ctx.halg, &ctx.public);
    if (!res) {
        return false;
    }

    TPM2B_DATA outside_info = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA createion_data = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;

    TSS2L_SYS_AUTH_COMMAND sessionsData =
            TSS2L_SYS_AUTH_COMMAND_INIT(1, {ctx.session_data});

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TSS2_RC rval = TSS2_RETRY_EXP(
            Tss2_Sys_CreatePrimary(sapi_context, ctx.hierarchy, &sessionsData,
                    &ctx.sensitive, &ctx.public, &outside_info,
                    &creation_pcr, &ctx.handle, &out_public, &createion_data,
                    &creation_hash, &creation_ticket, &name, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_CreatePrimary, rval);
        return false;
    }

    tpm2_util_tpma_object_to_yaml(ctx.public.publicArea.objectAttributes);
    tpm2_tool_output("handle: 0x%X", ctx.handle);

    return true;
}

static bool on_option(char key, char *value) {

    bool res;

    switch (key) {
    case 'H':
        res = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy,
                TPM2_HIERARCHY_FLAGS_ALL);
        if (!res) {
            return false;
        }
        ctx.flags.H = 1;
        break;
    case 'P':
        res = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!res) {
            LOG_ERR("Invalid parent key password, got\"%s\"", value);
            return false;
        }
        break;
    case 'K':
        res = tpm2_password_util_from_optarg(value,
                &ctx.sensitive.sensitive.userAuth);
        if (!res) {
            LOG_ERR("Invalid new key password, got\"%s\"", value);
            return false;
        }
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
            return false;
        }
        ctx.flags.g = 1;
        break;
    case 'G':
        ctx.public.publicArea.type = tpm2_alg_util_from_optarg(value);
        if (ctx.public.publicArea.type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got\"%s\"", value);
            return false;
        }
        ctx.flags.G = 1;
        break;
    case 'C':
        ctx.context_file = value;
        if (ctx.context_file == NULL || ctx.context_file[0] == '\0') {
            return false;
        }
        break;
    case 'L':
        ctx.public.publicArea.authPolicy.size = BUFFER_SIZE(TPM2B_DIGEST,
                buffer);
        if (!files_load_bytes_from_path(value,
                ctx.public.publicArea.authPolicy.buffer,
                &ctx.public.publicArea.authPolicy.size)) {
            return false;
        }
        break;
    case 'A': {
        bool res = tpm2_attr_util_obj_from_optarg(value,
                &ctx.public.publicArea.objectAttributes);
        if (!res) {
            LOG_ERR("Invalid object attribute, got\"%s\"", value);
            return false;
        }
    }
        break;
    case 'S': {
        tpm2_session *s = tpm2_session_restore(value);
        if (!s) {
            return false;
        }

        ctx.session_data.sessionHandle = tpm2_session_get_handle(s);
        tpm2_session_free(&s);
    }
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",            required_argument, NULL, 'H' },
        { "pwdp",                 required_argument, NULL, 'P' },
        { "pwdk",                 required_argument, NULL, 'K' },
        { "halg",                 required_argument, NULL, 'g' },
        { "kalg",                 required_argument, NULL, 'G' },
        { "context",              required_argument, NULL, 'C' },
        { "policy-file",          required_argument, NULL, 'L' },
        { "object-attributes",    required_argument, NULL, 'A' },
        { "input-session-handle", required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("A:P:K:g:G:C:L:S:H:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

static inline bool valid_ctx(struct tpm_createprimary_ctx ctx) {
    return (ctx.flags.H && ctx.flags.g && ctx.flags.G);
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {
    UNUSED(flags);

    if (!valid_ctx(ctx)) {
        return 1;
    }

    bool result = create_primary(sapi_context);
    if (!result) {
        return 1;
    }

    if (!ctx.context_file) {
        return 0;
    }

    result = files_save_tpm_context_to_path(sapi_context, ctx.handle,
            ctx.context_file);

    /* 0 on success, 1 otherwise */
    return !result;
}
