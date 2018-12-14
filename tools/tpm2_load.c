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
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
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
        UINT8 P : 1;
        UINT8 o : 1;
    } flags;
    ESYS_TR handle;
};

static tpm_load_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
};

int load (ESYS_CONTEXT *ectx) {

    int ret = 0;
    TPM2_RC rval;
    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.context_object.tr_handle,
                            &ctx.auth.session_data, ctx.auth.session);
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
        ctx.flags.P = 1;
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

    if(ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.parent_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid parent key authorization, got\"%s\"", ctx.parent_auth_str);
            goto out;
        }
    }

    tpm2_object_load_rc olrc = tpm2_util_object_load(ectx,
                                ctx.context_arg, &ctx.context_object);
    if (olrc == olrc_error) {
        goto out;
    } else if (!ctx.context_object.tr_handle) {
        result = tpm2_util_sys_handle_to_esys_handle(ectx,
                    ctx.context_object.handle,
                    &ctx.context_object.tr_handle);
        if (!result) {
            goto out;
        }
    }

    int tmp_rc = load(ectx);
    if (tmp_rc) {
        goto out;
    }

    if (!ctx.context_file || ctx.context_file[0] == '\0') {
        ctx.context_file = "object.ctx";
    }

    result = files_save_tpm_context_to_path(ectx,
                ctx.handle,
                ctx.context_file);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    result = tpm2_session_save(ectx, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
