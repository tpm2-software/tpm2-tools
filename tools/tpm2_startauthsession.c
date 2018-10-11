//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_startauthsession_ctx tpm2_startauthsession_ctx;
struct tpm2_startauthsession_ctx {
    struct {
        TPM2_SE type;
        TPMI_ALG_HASH halg;
    } session;
    struct {
        const char *path;
    } output;
};

static tpm2_startauthsession_ctx ctx = {
    .session = {
        .type = TPM2_SE_TRIAL,
        .halg = TPM2_ALG_SHA256
    }
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'a':
        ctx.session.type = TPM2_SE_POLICY;
        break;
    case 'g':
        ctx.session.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if(ctx.session.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'S':
        ctx.output.path = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "auth-policy-session", no_argument,       NULL, 'a'},
        { "policy-digest-alg",   required_argument, NULL, 'g'},
        { "session",             required_argument, NULL, 'S'},
    };

    *opts = tpm2_options_new("ag:S:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    tpm2_session_data *session_data = tpm2_session_data_new(ctx.session.type);
    if (!session_data) {
        LOG_ERR("oom");
        return rc;
    }

    tpm2_session_set_authhash(session_data, ctx.session.halg);

    tpm2_session *s = tpm2_session_new(ectx,
            session_data);
    if (!s) {
        return rc;
    }

    ESYS_TR session_handle = tpm2_session_get_handle(s);
    TPMI_SH_AUTH_SESSION tpm_handle;
    bool result = tpm2_util_esys_handle_to_sys_handle(ectx, session_handle,
                    &tpm_handle);
    if (!result) {
        goto out;
    }

    tpm2_tool_output("session-handle: 0x%" PRIx32 "\n", tpm_handle);

    if (ctx.output.path) {
        result = tpm2_session_save(ectx, s, ctx.output.path);
        if (!result) {
            goto out;
        }
    }

    rc = 0;

out:
    tpm2_session_free(&s);

    return rc;
}
