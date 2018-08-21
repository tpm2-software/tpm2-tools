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
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_capability.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPMI_RH_PROVISION hierarchy;
    TPMI_DH_PERSISTENT persist_handle;
    tpm2_loaded_object context_object;
    const char *context_arg;
    struct {
        UINT8 p : 1;
        UINT8 P : 1;
        UINT8 c : 1;
    } flags;
    char *hierarchy_auth_str;
};

static tpm_evictcontrol_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    .hierarchy = TPM2_RH_OWNER,
};

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            return false;
        }
        break;
    case 'p':
        result = tpm2_util_string_to_uint32(value, &ctx.persist_handle);
        if (!result) {
            LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.p = 1;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.hierarchy_auth_str = value;
        break;
    case 'c':
        ctx.context_arg = value;
        ctx.flags.c = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",      required_argument, NULL, 'a' },
      { "persistent",     required_argument, NULL, 'p' },
      { "auth-hierarchy", required_argument, NULL, 'P' },
      { "context",        required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("a:p:P:c:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    result = tpm2_util_object_load_sapi(sapi_context, ctx.context_arg,
                &ctx.context_object);
    if (!result) {
        goto out;
    }

    if (ctx.context_object.handle >> TPM2_HR_SHIFT == TPM2_HT_PERSISTENT) {
        ctx.persist_handle = ctx.context_object.handle;
        ctx.flags.p = 1;
    }

    /* If we've been given a handle or context object to persist and not an explicit persistent handle
     * to use, find an available vacant handle in the persistent namespace and use that.
     */
    if (ctx.flags.c && !ctx.flags.p) {
        result = tpm2_capability_find_vacant_persistent_handle(sapi_context,
                &ctx.persist_handle);
        if (!result) {
            tpm2_tool_output("Unable to find a vacant persistent handle.\n");
            goto out;
        }
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.hierarchy_auth_str,
               &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid authorization authorization, got\"%s\"",
                ctx.hierarchy_auth_str);
            goto out;
        }
    }

    tpm2_tool_output("persistentHandle: 0x%x\n", ctx.persist_handle);

    result = tpm2_ctx_mgmt_evictcontrol(sapi_context,
            ctx.hierarchy,
            &ctx.auth.session_data,
            ctx.context_object.handle,
            ctx.persist_handle);
    if (!result) {
        goto out;
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
