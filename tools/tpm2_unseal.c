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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm_hash.h"
#include "tpm_session.h"
#include "tpm2_password_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_unseal_ctx tpm_unseal_ctx;
struct tpm_unseal_ctx {
    TPMS_AUTH_COMMAND sessionData;
    TPMI_DH_OBJECT itemHandle;
    char *outFilePath;
    char *contextItemFile;
    char *raw_pcrs_file;
    SESSION *policy_session;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 H : 1;
        UINT8 c : 1;
        UINT8 P : 1;
        UINT8 L : 1;
        UINT8 F : 1;
    } flags;
};

static tpm_unseal_ctx ctx = {
        .sessionData = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW),
};

bool unseal_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    TPM2B_SENSITIVE_DATA outData = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_DATA, buffer);

    session_data_array[0] = &ctx.sessionData;
    session_data_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    TPM_RC rval = Tss2_Sys_Unseal(sapi_context, ctx.itemHandle,
            &sessions_data, &outData, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Sys_Unseal failed. Error Code: 0x%x", rval);
        return false;
    }

    if (ctx.outFilePath) {
        return files_save_bytes_to_file(ctx.outFilePath, (UINT8 *)
                                        outData.t.buffer, outData.t.size);
    } else {
        return files_write_bytes(stdout, (UINT8 *) outData.t.buffer,
                                 outData.t.size);
    }
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {

    if (!(ctx.flags.H || ctx.flags.c)) {
        LOG_ERR("Expected options H or c");
        return false;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_file(sapi_context, &ctx.itemHandle,
                ctx.contextItemFile);
        if (!result) {
            return false;
        }
    }

    if (ctx.flags.L && ctx.flags.F) {
        TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

        TPM_RC rval = tpm2_policy_build(sapi_context, &ctx.policy_session,
                                        TPM_SE_POLICY, TPM_ALG_SHA256, ctx.pcr_selection,
                                        ctx.raw_pcrs_file, &pcr_digest, true,
                                        tpm2_policy_pcr_build);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Building PCR policy failed: 0x%x", rval);
            return false;
        }

        ctx.sessionData.sessionHandle = ctx.policy_session->sessionHandle;
        ctx.sessionData.sessionAttributes.continueSession = 1;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'H': {
        bool result = tpm2_util_string_to_uint32(value, &ctx.itemHandle);
        if (!result) {
            LOG_ERR("Could not convert item handle to number, got: \"%s\"",
                    optarg);
            return false;
        }
        ctx.flags.H = 1;
    }
        break;
    case 'P': {
        bool result = tpm2_password_util_from_optarg(value, &ctx.sessionData.hmac);
        if (!result) {
            LOG_ERR("Invalid item handle password, got\"%s\"", optarg);
            return false;
        }
        ctx.flags.P = 1;
    }
        break;
    case 'o':
        ctx.outFilePath = optarg;
        break;
    case 'c':
        ctx.contextItemFile = optarg;
        ctx.flags.c = 1;
        break;
    case 'S': {
        bool result = tpm2_util_string_to_uint32(value,
            &ctx.sessionData.sessionHandle);
        if (!result) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    optarg);
            return false;
        }
    }
        break;
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = optarg;
        ctx.flags.F = 1;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      {"item",                 required_argument, NULL, 'H'},
      {"pwdk",                 required_argument, NULL, 'P'},
      {"outfile",              required_argument, NULL, 'o'},
      {"itemContext",          required_argument, NULL, 'c'},
      {"input-session-handle", required_argument, NULL, 'S'},
      {"set-list",             required_argument, NULL, 'L' },
      {"pcr-input-file",       required_argument, NULL, 'F' },
      {NULL,                   no_argument,       NULL, '\0'}
    };

    *opts = tpm2_options_new("H:P:o:c:S:L:F:", ARRAY_LEN(topts), topts,
            on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = init(sapi_context);
    if (!result) {
        return 1;
    }

    if (!unseal_and_save(sapi_context)) {
        LOG_ERR("Unseal failed!");
        return 1;
    }

    if (ctx.policy_session) {
        TPM_RC rval = Tss2_Sys_FlushContext(sapi_context,
                                            ctx.policy_session->sessionHandle);
        if (rval != TPM_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context: 0x%x", rval);
            return 1;
        }

        tpm_session_auth_end(ctx.policy_session);
    }

    return 0;
}
