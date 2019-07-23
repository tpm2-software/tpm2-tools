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
#include "object.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_load_ctx tpm_load_ctx;
struct tpm_load_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    TPM2B_PUBLIC  in_public;
    TPM2B_PRIVATE in_private;
    char *out_name_file;
    char *context_file;
    ESYS_TR handle;

    struct {
        UINT8 u : 1;
        UINT8 r : 1;
        UINT8 o : 1;
    } flags;
};

static tpm_load_ctx ctx;

tool_rc load (ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    tool_rc rc = tpm2_load(
                    ectx,
                    &ctx.parent.object,
                    &ctx.in_private,
                    &ctx.in_public,
                    &ctx.handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.out_name_file) {

        TPM2B_NAME *nameExt;

        rval = Esys_TR_GetName(ectx, ctx.handle, &nameExt);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_TR_GetName, rval);
            return tool_rc_from_tpm(rval);
        }

        bool result = files_save_bytes_to_file(ctx.out_name_file, nameExt->name, nameExt->size);
        free(nameExt);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    bool res;

    switch(key) {
    case 'P':
        ctx.parent.auth_str = value;
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
        ctx.parent.ctx_path = value;
        break;
    case 'c':
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
      { "auth",                 required_argument, NULL, 'P' },
      { "public",               required_argument, NULL, 'u' },
      { "private",              required_argument, NULL, 'r' },
      { "name",                 required_argument, NULL, 'n' },
      { "key-context",          required_argument, NULL, 'c' },
      { "parent-context",       required_argument, NULL, 'C' },
    };

    *opts = tpm2_options_new("P:u:r:n:C:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if ((!ctx.parent.ctx_path) || (!ctx.flags.u || !ctx.flags.r)) {
        LOG_ERR("Expected options C, u and r.");
        return tool_rc_option_error;
    }

    if (!ctx.context_file) {
        LOG_ERR("Expected option -o");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
        ctx.parent.auth_str, &ctx.parent.object, false, TPM2_HANDLES_ALL);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = load(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return files_save_tpm_context_to_path(ectx,
                ctx.handle,
                ctx.context_file);
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.parent.object.session);
}
