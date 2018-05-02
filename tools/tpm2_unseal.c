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

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hash.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm_unseal_ctx tpm_unseal_ctx;
struct tpm_unseal_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPMI_DH_OBJECT itemHandle;
    char *outFilePath;
    char *contextItemFile;
    char *raw_pcrs_file;
    char *session_file;
    char *parent_auth_str;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 H : 1;
        UINT8 c : 1;
        UINT8 P : 1;
        UINT8 L : 1;
    } flags;
};

static tpm_unseal_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
};

bool unseal_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_COMMAND sessions_data = { 1, { ctx.auth.session_data }};
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    TPM2B_SENSITIVE_DATA outData = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_DATA, buffer);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Unseal(sapi_context, ctx.itemHandle,
            &sessions_data, &outData, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Unseal, rval);
        return false;
    }

    if (ctx.outFilePath) {
        return files_save_bytes_to_file(ctx.outFilePath, (UINT8 *)
                                        outData.buffer, outData.size);
    } else {
        return files_write_bytes(stdout, (UINT8 *) outData.buffer,
                                 outData.size);
    }
}

static bool start_auth_session(TSS2_SYS_CONTEXT *sapi_context) {

    tpm2_session_data *session_data =
            tpm2_session_data_new(TPM2_SE_POLICY);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    ctx.auth.session = tpm2_session_new(sapi_context,
            session_data);
    if (!ctx.auth.session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    bool result = tpm2_policy_build_pcr(sapi_context, ctx.auth.session,
            ctx.raw_pcrs_file,
            &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build a pcr policy");
        return false;
    }

    ctx.auth.session_data.sessionHandle = tpm2_session_get_handle(ctx.auth.session);
    ctx.auth.session_data.sessionAttributes |= TPMA_SESSION_CONTINUESESSION;

    return true;
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {

    if (!(ctx.flags.H || ctx.flags.c)) {
        LOG_ERR("Expected options H or c");
        return false;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_path(sapi_context, &ctx.itemHandle,
                ctx.contextItemFile);
        if (!result) {
            return false;
        }
    }

    if (ctx.flags.L) {
        bool result = start_auth_session(sapi_context);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'H': {
        bool result = tpm2_util_string_to_uint32(value, &ctx.itemHandle);
        if (!result) {
            LOG_ERR("Could not convert item handle to number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.H = 1;
    }
        break;
    case 'P': {
        ctx.flags.P = 1;
        ctx.parent_auth_str = value;
    }
        break;
    case 'o':
        ctx.outFilePath = value;
        break;
    case 'c':
        ctx.contextItemFile = value;
        ctx.flags.c = 1;
        break;
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "item",                 required_argument, NULL, 'H' },
      { "auth-key",             required_argument, NULL, 'P' },
      { "out-file",             required_argument, NULL, 'o' },
      { "item-context",         required_argument, NULL, 'c' },
      { "set-list",             required_argument, NULL, 'L' },
      { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("H:P:o:c:L:F:", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init(sapi_context);
    if (!result) {
        goto out;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.parent_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid item handle authorization, got\"%s\"", ctx.parent_auth_str);
            goto out;
        }
    }

    result = unseal_and_save(sapi_context);
    if (!result) {
        LOG_ERR("Unseal failed!");
        goto out;
    }

    rc = 0;
out:

    if (ctx.flags.L) {
        /*
         * Only flush sessions started internally by the tool.
         */
        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context,
                            ctx.auth.session_data.sessionHandle));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_FlushContext, rval);
            rc = 1;
        }
    } else {
        result = tpm2_session_save(sapi_context, ctx.auth.session, NULL);
        if (!result) {
            rc = 1;
        }
    }

    return rc;
}

void tpm2_tool_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
