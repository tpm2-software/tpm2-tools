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

#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

typedef struct tpm_pcr_reset_ctx tpm_pcr_reset_ctx;
struct tpm_pcr_reset_ctx {
    bool            pcr_list[TPM2_MAX_PCRS];
};

static tpm_pcr_reset_ctx ctx;

static bool pcr_reset_one(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_PCR pcr_index) {
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TSS2L_SYS_AUTH_COMMAND sessions_data = { 1, {{ .sessionHandle=TPM2_RS_PW }}};

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PCR_Reset(sapi_context, pcr_index, &sessions_data,
            &sessions_data_out));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Could not reset PCR index: %d", pcr_index);
        return false;
    }

    return true;
}

static bool pcr_reset(TSS2_SYS_CONTEXT *sapi_context) {
    size_t i;

    for (i = 0; i < TPM2_MAX_PCRS; i++) {
        if(!ctx.pcr_list[i])
            continue;

        bool result = pcr_reset_one(sapi_context, i);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool on_arg(int argc, char** argv){
    int i;
    uint32_t pcr;

    memset(ctx.pcr_list, 0, TPM2_MAX_PCRS);
    
    if (argc < 1) {
        LOG_ERR("Expected at least one PCR index"
                "ie: <pcr index>, got: 0");
        return false;
    }

    for(i = 0; i < argc; i++){
        if(!tpm2_util_string_to_uint32(argv[i], &pcr)){
            LOG_ERR("Got invalid PCR Index: \"%s\"", argv[i]);
            return false;
        }

        /*
        * If any specified PCR index is greater than the last valid
        * index supported in the spec, throw an error 
        */
        if(pcr > TPM2_MAX_PCRS - 1){
            LOG_ERR("Got out of bound PCR Index: \"%s\"", argv[i]);
            return false;
        }

        ctx.pcr_list[pcr] = 1;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    return pcr_reset(sapi_context) != true;
}

