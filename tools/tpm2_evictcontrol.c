//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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
#include <strings.h>

#include "tpm2_password_util.h"
#include "files.h"
#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_RH_PROVISION auth;
    struct {
        TPMI_DH_OBJECT object;
        TPMI_DH_OBJECT persist;
    } handle;
    char *context_file;
    struct {
        UINT8 A : 1;
        UINT8 H : 1;
        UINT8 S : 1;
        UINT8 c : 1;
        UINT8 P : 1;
    } flags;
};

static tpm_evictcontrol_ctx ctx = {
    .session_data = TPMS_AUTH_COMMAND_EMPTY_INIT,
};

static int evict_control(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_COMMAND sessions_data;
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    sessions_data.count = 1;
    sessions_data.auths[0] = ctx.session_data;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, ctx.auth, ctx.handle.object,
                                        &sessions_data, ctx.handle.persist,&sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("EvictControl failed, error code: 0x%x", rval);
        return false;
    }
    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'A':
        if (!strcasecmp(value, "o")) {
            ctx.auth = TPM2_RH_OWNER;
        } else if (!strcasecmp(value, "p")) {
            ctx.auth = TPM2_RH_PLATFORM;
        } else {
            LOG_ERR("Incorrect auth value, got: \"%s\", expected [o|O|p|P!",
                    value);
            return false;
        }
        ctx.flags.A = 1;
        break;
    case 'H':
        result = tpm2_util_string_to_uint32(value, &ctx.handle.object);
        if (!result) {
            LOG_ERR("Could not convert object handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.H = 1;

        if (ctx.handle.object >> TPM2_HR_SHIFT == TPM2_HT_PERSISTENT) {
            ctx.handle.persist = ctx.handle.object;
            ctx.flags.S = 1;
        }
        break;
    case 'S':
        result = tpm2_util_string_to_uint32(value, &ctx.handle.persist);
        if (!result) {
            LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.S = 1;
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!result) {
            LOG_ERR("Invalid authorization password, got\"%s\"", value);
            return false;
        }
        ctx.flags.P = 1;
        break;
    case 'c':
        ctx.context_file = value;
        ctx.flags.c = 1;
        break;
    case 'i':
        if (!tpm2_util_string_to_uint32(value, &ctx.session_data.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    }

    return  true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"auth",        required_argument, NULL, 'A'},
      {"handle",      required_argument, NULL, 'H'},
      {"persistent",  required_argument, NULL, 'S'},
      {"pwda",        required_argument, NULL, 'P'},
      {"context",     required_argument, NULL, 'c'},
      {"input-session-handle", required_argument, NULL, 'i'},
    };

    ctx.session_data.sessionHandle = TPM2_RS_PW;

    *opts = tpm2_options_new("A:H:S:P:c:i:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!(ctx.flags.A && (ctx.flags.H || ctx.flags.c) && ctx.flags.S)) {
        LOG_ERR("Invalid arguments");
        return 1;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_file(sapi_context, &ctx.handle.object,
                                                       ctx.context_file);
        if (!result) {
            return 1;
        }
    }

    tpm2_tool_output("persistentHandle: 0x%x\n", ctx.handle.persist);

    return evict_control(sapi_context) != true;
}
