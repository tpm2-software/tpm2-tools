/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
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
    case 0:
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
        { "policy-session",      no_argument,       NULL,  0 },
        { "halg",                required_argument, NULL, 'g'},
        { "session",             required_argument, NULL, 'S'},
    };

    *opts = tpm2_options_new("g:S:", ARRAY_LEN(topts), topts, on_option,
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

    if (!ctx.output.path || ctx.output.path[0] == '\0') {
        ctx.output.path = "session.ctx";
    }

    char *ctx_file = NULL;
    bool result = files_get_unique_name(ctx.output.path, &ctx_file);
    if (!result) {
        goto out;
    }

    result = tpm2_session_save(ectx, s, ctx_file);
    if (!result) {
        goto out;
    }

    tpm2_tool_output("session-context: %s\n", ctx_file);

    rc = 0;

out:
    free(ctx_file);
    tpm2_session_free(&s);

    return rc;
}
