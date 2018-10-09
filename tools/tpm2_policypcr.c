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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_policypcr_ctx tpm2_policypcr_ctx;
struct tpm2_policypcr_ctx {
   const char *session_path;
   const char *raw_pcrs_file;
   TPML_PCR_SELECTION pcr_selection;
   const char *policy_out_path;
};

static tpm2_policypcr_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {
    case 'f':
        ctx.policy_out_path = value;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
        break;
    case 'L': {
        bool result = pcr_parse_selections(value, &ctx.pcr_selection);
        if (!result) {
            LOG_ERR("Could not parse PCR selections");
            return false;
        }
    } break;
    case 'S':
        ctx.session_path = value;
    break;
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy-file",    required_argument,  NULL,   'f' },
        { "pcr-input-file", required_argument,  NULL,   'F' },
        { "set-list",       required_argument,  NULL,   'L' },
        { "session",        required_argument,  NULL,   'S' },
    };

    *opts = tpm2_options_new("f:F:L:S:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    tpm2_session *s = NULL;

    bool fail = false;
    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        fail = true;
    }

    if (!ctx.pcr_selection.count) {
        LOG_ERR("Must specify -L pcr selection list.");
        fail = true;
    }

    if (fail) {
        return -1;
    }

    s = tpm2_session_restore(ectx, ctx.session_path);
    if (!s) {
        return rc;
    }


    bool result = tpm2_policy_build_pcr(ectx, s,
            ctx.raw_pcrs_file,
            &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build pcr policy");
        goto out;
    }

    TPM2B_DIGEST *policy_digest;
    result = tpm2_policy_get_digest(ectx, s,
            &policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        goto out_policy;
    }

    tpm2_tool_output("policy-digest: 0x");
    UINT16 i;
    for(i = 0; i < policy_digest->size; i++) {
        tpm2_tool_output("%02X", policy_digest->buffer[i]);
    }
    tpm2_tool_output("\n");

    if (ctx.policy_out_path) {
        result = files_save_bytes_to_file(ctx.policy_out_path,
                    (UINT8 *) &policy_digest->buffer,
                    policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    ctx.policy_out_path);
            goto out_policy;
        }
    }
    result = tpm2_session_save(ectx, s, ctx.session_path);
    if (!result) {
        LOG_ERR("Failed to save policy to file \"%s\"", ctx.session_path);
    }

    rc = 0;

out_policy:
    free(policy_digest);
out:
    tpm2_session_free(&s);
    return rc;
}
