/* SPDX-License-Identifier: BSD-3-Clause */

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
#include "tpm2.h"
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
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC public;
        char *sealed_data;
        char *public_path;
        char *private_path;
        char *auth_str;
        const char *ctx_path;
        char *alg;
        char *attrs;
        char *name_alg;
        char *policy;
    } object;

    struct {
        UINT8 b : 1;
        UINT8 i : 1;
        UINT8 L : 1;
        UINT8 u : 1;
        UINT8 r : 1;
        UINT8 G : 1;
    } flags;
};

#define DEFAULT_KEY_ALG "rsa2048"

static tpm_create_ctx ctx = {
        .object = { .alg = DEFAULT_KEY_ALG },
};

static tool_rc create(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_general_error;

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR = { .count = 0 };
    TPM2B_PUBLIC            *outPublic;
    TPM2B_PRIVATE           *outPrivate;

    ESYS_TR object_handle = ESYS_TR_NONE;
    if (ctx.object.ctx_path) {

        size_t offset = 0;
        TPM2B_TEMPLATE template = { .size = 0 };
        tool_rc tmp_rc = tpm2_mu_tpmt_public_marshal(&ctx.object.public.publicArea, &template.buffer[0],
                                        sizeof(TPMT_PUBLIC), &offset);
        if(tmp_rc != tool_rc_success) {
            return tmp_rc;
        }

        template.size = offset;

        tmp_rc = tpm2_create_loaded(
                ectx,
                &ctx.parent.object,
                &ctx.object.sensitive,
                &template,
                &object_handle,
                &outPrivate,
                &outPublic);
        if(tmp_rc != tool_rc_success) {
            return tmp_rc;
        }
    } else {
        TPM2B_CREATION_DATA     *creationData;
        TPM2B_DIGEST            *creationHash;
        TPMT_TK_CREATION        *creationTicket;
        tool_rc tmp_rc = tpm2_create(ectx, &ctx.parent.object,
                &ctx.object.sensitive, &ctx.object.public, &outsideInfo, &creationPCR,
                &outPrivate, &outPublic, &creationData, &creationHash,
                &creationTicket);
        if(tmp_rc != tool_rc_success) {
            return tmp_rc;
        }
        free(creationData);
        free(creationHash);
        free(creationTicket);
    }

    tpm2_util_public_to_yaml(outPublic, NULL);

    if (ctx.flags.u) {
        bool res = files_save_public(outPublic, ctx.object.public_path);
        if(!res) {
            goto out;
        }
    }

    if (ctx.flags.r) {
        bool res = files_save_private(outPrivate, ctx.object.private_path);
        if (!res) {
            goto out;
        }
    }

    if (ctx.object.ctx_path) {
        rc = files_save_tpm_context_to_path(ectx,
                    object_handle,
                    ctx.object.ctx_path);
    } else {
        rc = tool_rc_success;
    }

out:
    free(outPrivate);
    free(outPublic);

    return rc;
}

static bool on_option(char key, char *value) {

    switch(key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'p':
        ctx.object.auth_str = value;
    break;
    case 'g':
        ctx.object.name_alg = value;
    break;
    case 'G':
        ctx.object.alg =  value;
        ctx.flags.G = 1;
    break;
    case 'b':
        ctx.object.attrs = value;
        ctx.flags.b = 1;
    break;
    case 'i':
        ctx.object.sealed_data = strcmp("-", value) ? value : NULL;
        ctx.flags.i = 1;
        break;
    case 'L':
        ctx.object.policy = value;
        ctx.flags.L = 1;
        break;
    case 'u':
        ctx.object.public_path = value;
        ctx.flags.u = 1;
        break;
    case 'r':
        ctx.object.private_path = value;
        ctx.flags.r = 1;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'o':
        ctx.object.ctx_path = value;
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

    ctx.object.sensitive.sensitive.data.size = BUFFER_SIZE(typeof(ctx.object.sensitive.sensitive.data), buffer);
    return files_load_bytes_from_buffer_or_file_or_stdin(NULL,ctx.object.sealed_data,
            &ctx.object.sensitive.sensitive.data.size, ctx.object.sensitive.sensitive.data.buffer);
}

static tool_rc check_options(void) {

    if(!ctx.parent.ctx_path) {
        LOG_ERR("Must specify parent object via -C.");
        return tool_rc_option_error;
    }

    if (ctx.flags.i && ctx.flags.G) {
        LOG_ERR("Cannot specify -G and -i together.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMA_OBJECT attrs = DEFAULT_ATTRS;

    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.flags.i) {

        bool res = load_sensitive();
        if (!res) {
            return tool_rc_general_error;
        }

        ctx.object.alg = "keyedhash";

        if (!ctx.flags.b) {
            attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
            attrs &= ~TPMA_OBJECT_DECRYPT;
            attrs &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
        }
    } else if (!ctx.flags.b && !strncmp("hmac", ctx.object.alg, 4)) {
        attrs &= ~TPMA_OBJECT_DECRYPT;
    }

    bool result = tpm2_alg_util_public_init(ctx.object.alg, ctx.object.name_alg,
            ctx.object.attrs, ctx.object.policy, NULL, attrs,
            &ctx.object.public);
    if(!result) {
        return tool_rc_general_error;
    }

    if (ctx.flags.L && !ctx.object.auth_str) {
        ctx.object.public.publicArea.objectAttributes &= ~TPMA_OBJECT_USERWITHAUTH;
    }

    if (ctx.flags.i && ctx.object.public.publicArea.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        return tool_rc_general_error;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_session *tmp;
    rc = tpm2_auth_util_from_optarg(NULL, ctx.object.auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    TPM2B_AUTH const *auth = tpm2_session_get_auth_value(tmp);
    ctx.object.sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    return create(ectx);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.parent.object.session);
}
