//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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

#include <stdlib.h>

#include <sapi/tpm20.h>

#include "../lib/tpm2_options.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_pcr_extend_ctx tpm_pcr_extend_ctx;
struct tpm_pcr_extend_ctx {
    TSS2_SYS_CONTEXT *sapi_context;
    size_t digest_spec_len;
    tpm2_pcr_digest_spec *digest_spec;
};

static bool pcr_extend_one(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_PCR pcr_index, TPML_DIGEST_VALUES *digests) {

    /*
     * TODO SUPPORT AUTH VALUES HERE
     * Bug: https://github.com/01org/tpm2-tools/issues/388
     */
    TPMS_AUTH_COMMAND session_data = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW);

    TPMS_AUTH_RESPONSE session_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];
    TSS2_SYS_RSP_AUTHS sessions_data_out;

    TSS2_SYS_CMD_AUTHS sessions_data;

    session_data_array[0] = &session_data;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data.cmdAuthsCount = 1;
    sessions_data_out.rspAuthsCount = 1;

    TPM_RC rc = Tss2_Sys_PCR_Extend(sapi_context, pcr_index, &sessions_data,
            digests, &sessions_data_out);
    if (rc != TPM_RC_SUCCESS) {
        LOG_ERR("Could not extend pcr index: 0x%X, due to error: 0x%X",
                pcr_index, rc);
        return false;
    }

    return true;
}

static bool pcr_extend(tpm_pcr_extend_ctx *ctx) {

    size_t i;
    for (i = 0; i < ctx->digest_spec_len; i++) {
        tpm2_pcr_digest_spec *dspec = &ctx->digest_spec[i];
        bool result = pcr_extend_one(ctx->sapi_context, dspec->pcr_index,
                &dspec->digests);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool init(int argc, char *argv[], tpm_pcr_extend_ctx *ctx) {

    if (argc < 2) {
        LOG_ERR("Expected at least one PCR Digest specification,"
                "ie: <pcr index>:<hash alg>=<hash value>");
        return false;
    }

    /* this can never be negative */
    ctx->digest_spec_len = (size_t) argc - 1;

    ctx->digest_spec = calloc(ctx->digest_spec_len, sizeof(*ctx->digest_spec));
    if (!ctx->digest_spec) {
        LOG_ERR("oom");
        return false;
    }

    return pcr_parse_digest_list(&argv[1], ctx->digest_spec_len, ctx->digest_spec);
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused, avoid compiler warning */
    (void) opts;
    (void) envp;

    int rc = 1;
    tpm_pcr_extend_ctx ctx = {
        .sapi_context = sapi_context,
        .digest_spec = NULL
    };

    bool res = init(argc, argv, &ctx);
    if (!res) {
        goto out;
    }

    rc = pcr_extend(&ctx) != true;

out:
    free(ctx.digest_spec);
    return rc;
}
