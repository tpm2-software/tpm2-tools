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

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    tpm2_hierarchy_pdata objdata;
    char *context_file;
    struct {
        UINT8 g :1;
        UINT8 G :1;
        UINT8 P :1;
        UINT8 K :1;
    } flags;
    char *parent_auth_str;
    char *key_auth_str;
};

static tpm_createprimary_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    .objdata = TPM2_HIERARCHY_DATA_INIT
};


static bool set_name_alg(TPMI_ALG_HASH halg, TPM2B_PUBLIC *public) {

    switch(halg) {
    case TPM2_ALG_SHA1:
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SHA384:
    case TPM2_ALG_SHA512:
    case TPM2_ALG_SM3_256:
    case TPM2_ALG_NULL:
        public->publicArea.nameAlg = halg;
        return true;
    }

    LOG_ERR("name algorithm \"%s\" not supported!",
            tpm2_alg_util_algtostr(halg));

    return false;
}

static bool set_alg(TPMI_ALG_PUBLIC type, TPM2B_PUBLIC *public) {


    switch(type) {
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

    public->publicArea.type = type;

    return true;
}



static bool on_option(char key, char *value) {

    bool res;

    switch (key) {
    case 'a':
        res = tpm2_hierarchy_from_optarg(value, &ctx.objdata.in.hierarchy,
                TPM2_HIERARCHY_FLAGS_ALL);
        if (!res) {
            return false;
        }
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.parent_auth_str = value;
        break;
    case 'K': {
        ctx.flags.K = 1;
        ctx.key_auth_str = value;
    } break;
    case 'g': {
        TPMI_ALG_HASH halg = tpm2_alg_util_from_optarg(value);
        if (halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
            return false;
        }

        res = set_name_alg(halg, &ctx.objdata.in.public);
        if (!res) {
            return false;
        }
        ctx.flags.g = 1;
    }   break;
    case 'G': {
        TPMI_ALG_PUBLIC type = tpm2_alg_util_from_optarg(value);
        if (type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got\"%s\"", value);
            return false;
        }

        res = set_alg(type, &ctx.objdata.in.public);
        if (!res) {
            return false;
        }
        ctx.flags.G = 1;
    }   break;
    case 'C':
        ctx.context_file = value;
        if (ctx.context_file == NULL || ctx.context_file[0] == '\0') {
            return false;
        }
        break;
    case 'L': {
        TPM2B_DIGEST *auth_policy = &ctx.objdata.in.public.publicArea.authPolicy;
        auth_policy->size = BUFFER_SIZE(TPM2B_DIGEST, buffer);
        if (!files_load_bytes_from_path(value,
                auth_policy->buffer, &auth_policy->size)) {
            return false;
        }
    }   break;
    case 'A': {
        bool res = tpm2_attr_util_obj_from_optarg(value,
                &ctx.objdata.in.public.publicArea.objectAttributes);
        if (!res) {
            LOG_ERR("Invalid object attribute, got\"%s\"", value);
            return false;
        }
    }   break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",            required_argument, NULL, 'a' },
        { "auth-hierarchy",       required_argument, NULL, 'P' },
        { "auth-object",          required_argument, NULL, 'K' },
        { "halg",                 required_argument, NULL, 'g' },
        { "kalg",                 required_argument, NULL, 'G' },
        { "context",              required_argument, NULL, 'C' },
        { "policy-file",          required_argument, NULL, 'L' },
        { "object-attributes",    required_argument, NULL, 'A' },
    };

    *opts = tpm2_options_new("A:P:K:g:G:C:L:a:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

static inline bool valid_ctx(void) {
    return (ctx.flags.g && ctx.flags.G);
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {
    UNUSED(flags);

    bool result;
    int rc = 1;

    if (!valid_ctx()) {
        goto out;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.parent_auth_str, &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
            goto out;
        }
    }

    if (ctx.flags.K) {
        TPMS_AUTH_COMMAND tmp;
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.key_auth_str, &tmp, NULL);
        if (!result) {
            LOG_ERR("Invalid new key authorization, got\"%s\"", ctx.key_auth_str);
            goto out;
        }
        ctx.objdata.in.sensitive.sensitive.userAuth = tmp.hmac;
    }

    result = tpm2_hierarchy_create_primary(sapi_context, &ctx.auth.session_data, &ctx.objdata);
    if (!result) {
        goto out;
    }

    tpm2_util_tpma_object_to_yaml(ctx.objdata.in.public.publicArea.objectAttributes);
    tpm2_tool_output("handle: 0x%X\n", ctx.objdata.out.handle);

    if (ctx.context_file) {
        result = files_save_tpm_context_to_path(sapi_context, ctx.objdata.out.handle,
            ctx.context_file);
        if (!result) {
            goto out;
        }
    }

    rc = 0;

out:
    result = tpm2_session_save(sapi_context, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
