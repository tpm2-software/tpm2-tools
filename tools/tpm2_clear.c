/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_password_util.h"

typedef struct clear_ctx clear_ctx;
struct clear_ctx {
    bool platform;
    TPMS_AUTH_COMMAND session_data;
};

static clear_ctx ctx = {
    .platform = false,
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
};

static bool clear(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_COMMAND sessionsData = { 1, { ctx.session_data }};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPMI_RH_CLEAR rh = TPM2_RH_LOCKOUT;

    LOG_INFO ("Sending TPM2_Clear command with %s",
            ctx.platform ? "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");
    if (ctx.platform)
        rh = TPM2_RH_PLATFORM;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Clear (sapi_context,
            rh, &sessionsData, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Tss2_Sys_Clear, rval);
        return false;
    }

    LOG_INFO ("Success. TSS2_RC: 0x%x", rval);
    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'p':
        ctx.platform = true;
        break;
    case 'L':
        result = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!result) {
            LOG_ERR("Invalid lockout password, got\"%s\"", value);
            return false;
        }
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "platform",       no_argument,       NULL, 'p' },
        { "lockout-passwd", required_argument, NULL, 'L' },
    };

    *opts = tpm2_options_new("pL:", ARRAY_LEN(topts), topts, on_option, NULL,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    return clear(sapi_context) != true;
}
