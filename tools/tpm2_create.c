/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

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

#define DEFAULT_ATTRS \
     TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM \
    |TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN \
    |TPMA_OBJECT_USERWITHAUTH

typedef struct tpm_create_ctx tpm_create_ctx;
struct tpm_create_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPM2B_SENSITIVE_CREATE in_sensitive;
    TPM2B_PUBLIC in_public;
    char *input;
    char *opu_path;
    char *opr_path;
    char *key_auth_str;
    char *parent_auth_str;
    const char *parent_ctx_path;
    const char *object_ctx_path;
    tpm2_loaded_object context_object;

    char *alg;
    char *attrs;
    char *halg;
    char *policy;

    struct {
        UINT16 P : 1;
        UINT16 p : 1;
        UINT16 b : 1;
        UINT16 i : 1;
        UINT16 L : 1;
        UINT16 u : 1;
        UINT16 r : 1;
        UINT16 G : 1;
    } flags;
};

#define DEFAULT_KEY_ALG "rsa2048"

static tpm_create_ctx ctx = {
        .alg = DEFAULT_KEY_ALG,
    .auth = {
            .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    },
};

static bool create(ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    bool ret = false;

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR = { .count = 0 };
    TPM2B_PUBLIC            *outPublic;
    TPM2B_PRIVATE           *outPrivate;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.context_object.tr_handle,
                            &ctx.auth.session_data, ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle");
        return false;
    }

    ESYS_TR object_handle = ESYS_TR_NONE;
    if (ctx.object_ctx_path) {

        size_t offset = 0;
        TPM2B_TEMPLATE template = { .size = 0 };
        rval = Tss2_MU_TPMT_PUBLIC_Marshal(&ctx.in_public.publicArea, &template.buffer[0],
                                        sizeof(TPMT_PUBLIC), &offset);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_MU_TPMT_PUBLIC_Marshal, rval);
            return false;
        }

        template.size = offset;

        TSS2_RC rval = Esys_CreateLoaded(
                ectx,
                ctx.context_object.tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &ctx.in_sensitive,
                &template,
                &object_handle,
                &outPrivate,
                &outPublic);
        if(rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_CreateLoaded, rval);
            return false;
        }
    } else {
        TPM2B_CREATION_DATA     *creationData;
        TPM2B_DIGEST            *creationHash;
        TPMT_TK_CREATION        *creationTicket;
        rval = Esys_Create(ectx, ctx.context_object.tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &ctx.in_sensitive, &ctx.in_public, &outsideInfo, &creationPCR,
                &outPrivate, &outPublic, &creationData, &creationHash,
                &creationTicket);
        if(rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_Create, rval);
            return false;
        }
        free(creationData);
        free(creationHash);
        free(creationTicket);
    }

    tpm2_util_public_to_yaml(outPublic, NULL);

    if (ctx.flags.u) {
        bool res = files_save_public(outPublic, ctx.opu_path);
        if(!res) {
            goto out;
        }
    }

    if (ctx.flags.r) {
        bool res = files_save_private(outPrivate, ctx.opr_path);
        if (!res) {
            goto out;
        }
    }

    if (ctx.object_ctx_path) {
        ret = files_save_tpm_context_to_path(ectx,
                    object_handle,
                    ctx.object_ctx_path);
        if (!ret) {
            goto out;
        }
    }

    ret = true;

out:
    free(outPrivate);
    free(outPublic);

    return ret;
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'P':
        /*
         * since the auth for the parent key may be a session, we need to
         * move this call to tpm2_auth_util_from_optarg to the
         * tpm2_tool_onrun function.
         */
        ctx.flags.P = 1;
        ctx.parent_auth_str = value;
        break;
    case 'p':
        ctx.flags.p = 1;
        ctx.key_auth_str = value;
    break;
    case 'g':
        ctx.halg = value;
    break;
    case 'G':
        ctx.alg =  value;
        ctx.flags.G = 1;
    break;
    case 'b':
        ctx.attrs = value;
        ctx.flags.b = 1;
    break;
    case 'i':
        ctx.input = strcmp("-", value) ? value : NULL;
        ctx.flags.i = 1;
        break;
    case 'L':
        ctx.policy = value;
        ctx.flags.L = 1;
        break;
    case 'u':
        ctx.opu_path = value;
        ctx.flags.u = 1;
        break;
    case 'r':
        ctx.opr_path = value;
        ctx.flags.r = 1;
        break;
    case 'C':
        ctx.parent_ctx_path = value;
        break;
    case 'o':
        ctx.object_ctx_path = value;
        break;
    };

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "auth-parent",          required_argument, NULL, 'P' },
      { "auth-key",             required_argument, NULL, 'p' },
      { "halg",                 required_argument, NULL, 'g' },
      { "kalg",                 required_argument, NULL, 'G' },
      { "object-attributes",    required_argument, NULL, 'b' },
      { "in-file",              required_argument, NULL, 'i' },
      { "policy-file",          required_argument, NULL, 'L' },
      { "pubfile",              required_argument, NULL, 'u' },
      { "privfile",             required_argument, NULL, 'r' },
      { "context-parent",       required_argument, NULL, 'C' },
      { "out-context",          required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("P:p:g:G:b:i:L:u:r:C:o:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static bool load_sensitive(void) {

    ctx.in_sensitive.sensitive.data.size = BUFFER_SIZE(typeof(ctx.in_sensitive.sensitive.data), buffer);
    return files_load_bytes_from_buffer_or_file_or_stdin(NULL,ctx.input,
            &ctx.in_sensitive.sensitive.data.size, ctx.in_sensitive.sensitive.data.buffer);
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    TPMA_OBJECT attrs = DEFAULT_ATTRS;

    if(!ctx.parent_ctx_path) {
        LOG_ERR("Must specify parent object via -C.");
        return -1;
    }

    if (ctx.flags.i) {
        if (ctx.flags.G) {
            LOG_ERR("Cannot specify -G and -i together.");
            return -1;
        }

        bool res = load_sensitive();
        if (!res) {
            goto out;
        }

        ctx.alg = "keyedhash";

        if (!ctx.flags.b) {
            attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
            attrs &= ~TPMA_OBJECT_DECRYPT;
            attrs &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
        }
    } else if (!ctx.flags.b && !strncmp("hmac", ctx.alg, 4)) {
        attrs &= ~TPMA_OBJECT_DECRYPT;
    }

    result = tpm2_alg_util_public_init(ctx.alg, ctx.halg, ctx.attrs, ctx.policy, NULL,
            attrs, &ctx.in_public);
    if(!result) {
        goto out;
    }

    if (ctx.flags.L && !ctx.flags.p) {
        ctx.in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_USERWITHAUTH;
    }

    if (ctx.flags.i && ctx.in_public.publicArea.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        goto out;
    }

    result = tpm2_util_object_load(ectx, ctx.parent_ctx_path,
            &ctx.context_object);
    if (!result) {
        goto out;
    }

    if (ctx.flags.p) {
        TPMS_AUTH_COMMAND tmp;
        result = tpm2_auth_util_from_optarg(ectx, ctx.key_auth_str, &tmp, NULL);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.key_auth_str);
            goto out;
        }
        ctx.in_sensitive.sensitive.userAuth = tmp.hmac;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.parent_auth_str,
            &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
            goto out;
        }
    }

    result = create(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    result = tpm2_session_save (ectx, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
