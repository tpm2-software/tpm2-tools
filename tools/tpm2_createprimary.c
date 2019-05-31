/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

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

#define DEFAULT_ATTRS \
     TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
    |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
    |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH

#define DEFAULT_PRIMARY_KEY_ALG "rsa2048:null:aes128cfb"

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    struct {
        char *auth_str;
        tpm2_session *session;
    } parent;

    tpm2_hierarchy_pdata objdata;
    char *context_file;
    char *unique_file;
    char *key_auth_str;

    char *alg;
    char *halg;
    char *attrs;
    char *policy;
};

static tpm_createprimary_ctx ctx = {
    .alg = DEFAULT_PRIMARY_KEY_ALG,
    .objdata = {
        .in = {
            .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
            .hierarchy = TPM2_RH_OWNER
        },
    },
};

static bool on_option(char key, char *value) {

    bool res;

    switch (key) {
    case 'a': {
        res = tpm2_hierarchy_from_optarg(value, &ctx.objdata.in.hierarchy,
                TPM2_HIERARCHY_FLAGS_ALL);

        if (!res) {
            return false;
        }
        break;
    }
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'p':
        ctx.key_auth_str = value;
        break;
    case 'g':
        ctx.halg = value;
        break;
    case 'G':
        ctx.alg = value;
        break;
    case 'o':
        ctx.context_file = value;
        break;
    case 'u':
        ctx.unique_file = value;
        if (ctx.unique_file == NULL || ctx.unique_file[0] == '\0') {
            return false;
        }
        break;
    case 'L':
        ctx.policy=value;
    break;
    case 'b':
        ctx.attrs = value;
    break;
    /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",            required_argument, NULL, 'a' },
        { "auth-hierarchy",       required_argument, NULL, 'P' },
        { "auth-object",          required_argument, NULL, 'p' },
        { "halg",                 required_argument, NULL, 'g' },
        { "kalg",                 required_argument, NULL, 'G' },
        { "out-context-name",     required_argument, NULL, 'o' },
        { "policy-file",          required_argument, NULL, 'L' },
        { "object-attributes",    required_argument, NULL, 'b' },
        { "unique-data",          required_argument, NULL, 'u' },
    };

    *opts = tpm2_options_new("b:P:p:g:G:o:L:a:u:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    bool result = tpm2_auth_util_from_optarg(ectx, ctx.parent.auth_str, &ctx.parent.session, false);
    if (!result) {
        LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent.auth_str);
        return tool_rc_general_error;
    }

    tpm2_session *tmp;
    result = tpm2_auth_util_from_optarg(NULL, ctx.key_auth_str, &tmp, true);
    if (!result) {
        LOG_ERR("Invalid new key authorization, got\"%s\"", ctx.key_auth_str);
        return tool_rc_general_error;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.objdata.in.sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    result = tpm2_alg_util_public_init(ctx.alg, ctx.halg, ctx.attrs, ctx.policy, ctx.unique_file, DEFAULT_ATTRS,
            &ctx.objdata.in.public);
    if(!result) {
        return tool_rc_general_error;
    }

    result = tpm2_hierarchy_create_primary(ectx,
                ctx.parent.session, &ctx.objdata);
    if (!result) {
        return tool_rc_general_error;
    }

    tpm2_util_public_to_yaml(ctx.objdata.out.public, NULL);

    return ctx.context_file ? files_save_tpm_context_to_path(ectx, ctx.objdata.out.handle,
        ctx.context_file) : tool_rc_success;
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.parent.session);
}

void tpm2_onexit(void) {

    tpm2_hierarchy_pdata_free(&ctx.objdata);
}
