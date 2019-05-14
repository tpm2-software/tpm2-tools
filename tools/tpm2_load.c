/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_load_ctx tpm_load_ctx;
struct tpm_load_ctx {
    struct {
        char *auth_str;
        tpm2_session *session;
    } parent;
    TPM2B_PUBLIC  in_public;
    TPM2B_PRIVATE in_private;
    char *out_name_file;
    char *context_file;
    char *parent_auth_str;
    const char *context_arg;
    tpm2_loaded_object context_object;
    struct {
        UINT8 u : 1;
        UINT8 r : 1;
        UINT8 o : 1;
    } flags;
    ESYS_TR handle;
};

static tpm_load_ctx ctx;

int load (ESYS_CONTEXT *ectx) {

    int ret = 0;
    TPM2_RC rval;
    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.context_object.tr_handle,
                            ctx.parent.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return -1;
    }

    rval = Esys_Load(ectx, ctx.context_object.tr_handle,
            shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
            &ctx.in_private, &ctx.in_public, &ctx.handle);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_PERR(Eys_Load, rval);
        return -1;
    }

    if (ctx.out_name_file) {

        TPM2B_NAME *nameExt;

        rval = Esys_TR_GetName(ectx, ctx.handle, &nameExt);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_TR_GetName, rval);
            ret = -1;
            goto done;
        }

        if(!files_save_bytes_to_file(ctx.out_name_file, nameExt->name, nameExt->size)) {
            ret = -2;
        }

    done:
        free(nameExt);
    }

    return ret;
}

static bool on_option(char key, char *value) {

    bool res;

    switch(key) {
    case 'P':
        ctx.parent_auth_str = value;
        break;
    case 'u':
        if(!files_load_public(value, &ctx.in_public)) {
            return false;;
        }
        ctx.flags.u = 1;
        break;
    case 'r':
        res = files_load_private(value, &ctx.in_private);
        if(!res) {
            return false;
        }
        ctx.flags.r = 1;
        break;
    case 'n':
        ctx.out_name_file = value;
        break;
    case 'C':
        ctx.context_arg = value;
        break;
    case 'o':
        ctx.context_file = value;
        if(ctx.context_file == NULL || ctx.context_file[0] == '\0') {
            return false;
        }
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth-parent",          required_argument, NULL, 'P' },
      { "pubfile",              required_argument, NULL, 'u' },
      { "privfile",             required_argument, NULL, 'r' },
      { "name",                 required_argument, NULL, 'n' },
      { "out-context",          required_argument, NULL, 'o' },
      { "context-parent",       required_argument, NULL, 'C' },
    };

    *opts = tpm2_options_new("P:u:r:n:C:o:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    if ((!ctx.context_arg) || (!ctx.flags.u || !ctx.flags.r)) {
        LOG_ERR("Expected options C, u and r.");
        return -1;
    }

    if (!ctx.context_file) {
        LOG_ERR("Expected option -o");
        return -1;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.parent_auth_str,
            &ctx.parent.session, false);
    if (!result) {
        LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
        goto out;
    }

    result = tpm2_util_object_load(ectx,
                                ctx.context_arg, &ctx.context_object);
    if (!result) {
        goto out;
    }

    int tmp_rc = load(ectx);
    if (tmp_rc) {
        goto out;
    }

    result = files_save_tpm_context_to_path(ectx,
                ctx.handle,
                ctx.context_file);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    result = tpm2_session_close(&ctx.parent.session);
    if (!result) {
        rc = 1;
    }

    return rc;
}
