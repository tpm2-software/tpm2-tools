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

#include <getopt.h>
#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"

typedef struct tpm_loadexternal_ctx tpm_loadexternal_ctx;
struct tpm_loadexternal_ctx {
    char *context_file_path;
    TPMI_RH_HIERARCHY hierarchy_value;
    TPM_HANDLE rsa2048_handle;
    TPM2B_PUBLIC public_key;
    TPM2B_SENSITIVE private_key;
    bool has_private_key;
    bool save_to_context_file;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool get_hierarchy_value(const char *argument_opt,
        TPMI_RH_HIERARCHY *hierarchy_value) {

    if (strlen(argument_opt) != 1) {
        LOG_ERR("Wrong Hierarchy Value, got: \"%s\", expected one of e,o,p,n",
                argument_opt);
        return false;
    }

    switch (argument_opt[0]) {
    case 'e':
        *hierarchy_value = TPM_RH_ENDORSEMENT;
        break;
    case 'o':
        *hierarchy_value = TPM_RH_OWNER;
        break;
    case 'p':
        *hierarchy_value = TPM_RH_PLATFORM;
        break;
    case 'n':
        *hierarchy_value = TPM_RH_NULL;
        break;
    default:
        LOG_ERR("Wrong Hierarchy Value, got: \"%s\", expected one of e,o,p,n",
                argument_opt);
        return false;
    }

    return true;
}

static bool load_external(tpm_loadexternal_ctx *ctx) {

    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_NAME nameExt = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    TPM_RC rval = Tss2_Sys_LoadExternal(ctx->sapi_context, 0,
            ctx->has_private_key ? &ctx->private_key : NULL, &ctx->public_key,
            ctx->hierarchy_value, &ctx->rsa2048_handle, &nameExt,
            &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("LoadExternal Failed ! ErrorCode: 0x%0x", rval);
        return false;
    }

    return true;
}

static bool init(int argc, char *argv[], tpm_loadexternal_ctx *ctx) {

    const char *optstring = "H:u:r:C:";
    static struct option long_options[] = {
      { "Hierachy", required_argument, NULL, 'H'},
      { "pubfile",  required_argument, NULL, 'u'},
      { "privfile", required_argument, NULL, 'r'},
      { "context",  required_argument, NULL, 'C'},
      { NULL,       no_argument,       NULL, '\0' }
    };

    union {
        struct {
            UINT8 H : 1;
            UINT8 u : 1;
            UINT8 unused : 6;
        };
        UINT8 all;
    } flags = { .all = 0 };

    if(argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt = -1;
    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'H': {
            bool result = get_hierarchy_value(optarg, &ctx->hierarchy_value);
            if (!result) {
                return false;
            }
        }
        flags.H = 1;
        break;
        case 'u': {
            UINT16 size = sizeof(ctx->public_key);
            bool result = files_load_bytes_from_path(optarg, (UINT8 *)&ctx->public_key, &size);
            if (!result) {
                return false;
            }
            flags.u = 1;
        } break;
        case 'r': {
            UINT16 size = sizeof(ctx->private_key);
            bool result = files_load_bytes_from_path(optarg, (UINT8 *)&ctx->private_key, &size);
            if (!result) {
                return false;
            }
            ctx->has_private_key = true;
        } break;
        case 'C':
            ctx->context_file_path = optarg;
            ctx->save_to_context_file = true;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??", opt);
            return false;
        }
    }

    if (!(flags.H && flags.u)) {
        LOG_ERR("Expected H and u options");
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts and envp are unused, avoid compiler warning */
    (void)opts;
    (void) envp;

    tpm_loadexternal_ctx ctx = {
            .has_private_key = false,
            .save_to_context_file = false,
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if(!result) {
        return 1;
    }

    result = load_external(&ctx);
    if (!result) {
        return 1;
    }

    if(ctx.save_to_context_file) {
            return files_save_tpm_context_to_file(ctx.sapi_context, ctx.rsa2048_handle,
                    ctx.context_file_path) != true;
    }

    return 0;
}
