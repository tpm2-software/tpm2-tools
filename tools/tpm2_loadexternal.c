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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "tpm2_options.h"
#include "files.h"
#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_hierarchy.h"

typedef struct tpm_loadexternal_ctx tpm_loadexternal_ctx;
struct tpm_loadexternal_ctx {
    char *context_file_path;
    TPMI_RH_HIERARCHY hierarchy_value;
    TPM2_HANDLE handle;
    TPM2B_PUBLIC public_key;
    TPM2B_SENSITIVE private_key;
    bool save_to_context_file;
    struct {
        UINT8 u : 1;
    } flags;
};

static tpm_loadexternal_ctx ctx = {
    .hierarchy_value = TPM2_RH_OWNER,
};

static bool load_external(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_NAME nameExt = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_LoadExternal(sapi_context, 0,
            ctx.private_key.size ? &ctx.private_key : NULL, &ctx.public_key,
            ctx.hierarchy_value, &ctx.handle, &nameExt,
            &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_LoadExternal, rval);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch(key) {
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy_value,
                   TPM2_HIERARCHY_FLAGS_ALL);
        if (!result) {
            return false;
        }
        break;
    case 'u':
        if(!files_load_public(value, &ctx.public_key)) {
            return false;;
        }
        ctx.flags.u = 1;
        break;
    case 'r':
        result = files_load_sensitive(value, &ctx.private_key);
        if (!result) {
            return false;
        }
        break;
    case 'o':
        ctx.context_file_path = value;
        ctx.save_to_context_file = true;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",    required_argument, NULL, 'a'},
      { "pubfile",      required_argument, NULL, 'u'},
      { "privfile",     required_argument, NULL, 'r'},
      { "out-context",  required_argument, NULL, 'o'},
    };

    *opts = tpm2_options_new("a:u:r:o:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.flags.u) {
        LOG_ERR("Expected u option");
        return 1;
    }

    bool result = load_external(sapi_context);
    if (!result) {
        return 1;
    }

    tpm2_tool_output("0x%X\n", ctx.handle);

    if(ctx.save_to_context_file) {
            return files_save_tpm_context_to_path(sapi_context, ctx.handle,
                    ctx.context_file_path) != true;
    }

    return 0;
}
