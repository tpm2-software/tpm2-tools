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

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct dictionarylockout_ctx dictionarylockout_ctx;
struct dictionarylockout_ctx {
    UINT32 max_tries;
    UINT32 recovery_time;
    UINT32 lockout_recovery_time;
    bool clear_lockout;
    bool setup_parameters;
    bool use_passwd;
    TPMS_AUTH_COMMAND session_data;
};

static dictionarylockout_ctx ctx = {
    .use_passwd = true,
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
};

bool dictionary_lockout_reset_and_parameter_setup(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 1, { ctx.session_data }};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * preceed parameters setup.
     */
    if (ctx.clear_lockout) {

        LOG_INFO("Resetting dictionary lockout state.");
        UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_DictionaryAttackLockReset(sapi_context,
                TPM2_RH_LOCKOUT, &sessionsData, &sessionsDataOut));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_DictionaryAttackLockReset, rval);
            return false;
        }
    }

    if (ctx.setup_parameters) {
        LOG_INFO("Setting up Dictionary Lockout parameters.");
        UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_DictionaryAttackParameters(sapi_context,
                TPM2_RH_LOCKOUT, &sessionsData, ctx.max_tries,
                ctx.recovery_time, ctx.lockout_recovery_time,
                &sessionsDataOut));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_DictionaryAttackParameters, rval);
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.clear_lockout = true;
        break;
    case 's':
        ctx.setup_parameters = true;
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!result) {
            LOG_ERR("Invalid lockout password, got\"%s\"", value);
            return false;
        }
        ctx.use_passwd = true;
        break;
    case 'n':
        result = tpm2_util_string_to_uint32(value, &ctx.max_tries);
        if (!result) {
            LOG_ERR("Could not convert max_tries to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.max_tries == 0) {
            return false;
        }
        break;
    case 't':
        result = tpm2_util_string_to_uint32(value, &ctx.recovery_time);
        if (!result) {
            LOG_ERR("Could not convert recovery_time to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 'l':
        result = tpm2_util_string_to_uint32(value, &ctx.lockout_recovery_time);
        if (!result) {
            LOG_ERR("Could not convert lockout_recovery_time to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 'S': {
        tpm2_session *s = tpm2_session_restore(value);
        if (!s) {
            return false;
        }

        ctx.session_data.sessionHandle = tpm2_session_get_handle(s);
        tpm2_session_free(&s);
    } break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "max-tries",             required_argument, NULL, 'n' },
        { "recovery-time",         required_argument, NULL, 't' },
        { "lockout-recovery-time", required_argument, NULL, 'l' },
        { "lockout-passwd",        required_argument, NULL, 'P' },
        { "clear-lockout",         no_argument,       NULL, 'c' },
        { "setup-parameters",      no_argument,       NULL, 's' },
        { "input-session-handle",  required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("n:t:l:P:S:cs", ARRAY_LEN(topts), topts, on_option,
                             NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.clear_lockout && !ctx.setup_parameters) {
        LOG_ERR( "Invalid operational input: Neither Setup nor Clear lockout requested.");
        return 1;
    }

    return dictionary_lockout_reset_and_parameter_setup(sapi_context) != true;
}
