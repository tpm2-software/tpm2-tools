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

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <stdbool.h>

#include <sapi/tpm20.h>

#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "log.h"
#include "tpm2_util.h"
#include "files.h"
#include "tpm2_tool.h"

TPM_HANDLE handle2048rsa;

typedef struct tpm_load_ctx tpm_load_ctx;
struct tpm_load_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_DH_OBJECT parent_handle;
    TPM2B_PUBLIC  in_public;
    TPM2B_PRIVATE in_private;
    char *out_file;
    char *context_file;
    char *context_parent_file;
    struct {
        UINT8 H : 1;
        UINT8 u : 1;
        UINT8 r : 1;
        UINT8 c : 1;
        UINT8 C : 1;
    } flags;
};

static tpm_load_ctx ctx = {
    .session_data = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0)
    }
};

int load (TSS2_SYS_CONTEXT *sapi_context) {
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_NAME nameExt = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    sessionDataArray[0] = &ctx.session_data;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sapi_context,
                         ctx.parent_handle,
                         &sessionsData,
                         &ctx.in_private,
                         &ctx.in_public,
                         &handle2048rsa,
                         &nameExt,
                         &sessionsDataOut));
    if(rval != TPM_RC_SUCCESS)
    {
        LOG_ERR("\nLoad Object Failed ! ErrorCode: 0x%0x\n",rval);
        return -1;
    }
    tpm2_tool_output("\nLoad succ.\nLoadedHandle: 0x%08x\n\n",handle2048rsa);

    if (ctx.out_file) {
        if(!files_save_bytes_to_file(ctx.out_file, nameExt.t.name, nameExt.t.size)) {
            return -2;
        }
    }

    return 0;
}

static bool on_option(char key, char *value) {

    bool res;

    switch(key) {
    case 'H':
        if (!tpm2_util_string_to_uint32(optarg, &ctx.parent_handle)) {
                return false;
        }
        ctx.flags.H = 1;
        break;
    case 'P':
        res = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!res) {
            LOG_ERR("Invalid parent key password, got\"%s\"", value);
            return false;
        }
        break;
    case 'u':
        if(!files_load_public(optarg, &ctx.in_public)) {
            return false;;
        }
        ctx.flags.u = 1;
        break;
    case 'r':
        ctx.in_private.t.size = sizeof(ctx.in_private.t.buffer);
        if(!files_load_bytes_from_path(value, ctx.in_private.t.buffer, &ctx.in_private.t.size)) {
            return false;
        }
        ctx.flags.r = 1;
        break;
    case 'n':
        ctx.out_file = value;
        if(files_does_file_exist(ctx.out_file)) {
            return false;
        }
        break;
    case 'c':
        ctx.context_parent_file = value;
        if(ctx.context_parent_file == NULL || ctx.context_parent_file[0] == '\0') {
                return false;
        }
        ctx.flags.c = 1;
        break;
    case 'C':
        ctx.context_file = value;
        if(ctx.context_file == NULL || ctx.context_file[0] == '\0') {
            return false;
        }
        ctx.flags.C = 1;
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.session_data.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"parent",1,NULL,'H'},
      {"pwdp",1,NULL,'P'},
      {"pubfile",1,NULL,'u'},
      {"privfile",1,NULL,'r'},
      {"name",1,NULL,'n'},
      {"context",1,NULL,'C'},
      {"context-parent",1,NULL,'c'},
      {"input-session-handle",1,NULL,'S'},
      {0,0,0,0}
    };

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    tpm2_option_flags empty_flags = tpm2_option_flags_init(0);
    *opts = tpm2_options_new("H:P:u:r:n:C:c:S:", ARRAY_LEN(topts), topts,
            on_option, NULL, empty_flags);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int returnVal = 0;

    if ((!ctx.flags.H && !ctx.flags.c) || (!ctx.flags.u || !ctx.flags.r)) {
        LOG_ERR("Expected options (H or c) and u and r");
        return 1;
    }

    if(ctx.flags.c) {
        returnVal = files_load_tpm_context_from_file(sapi_context,
                                               &ctx.parent_handle,
                                               ctx.context_parent_file) != true;
        if (returnVal) {
            return 1;
        }
    }

    returnVal = load(sapi_context);
    if (returnVal) {
        return 1;
    }

    if (ctx.flags.C) {
        returnVal = files_save_tpm_context_to_file (sapi_context,
                                                    handle2048rsa,
                                                    ctx.context_file) != true;
        if (returnVal) {
            return 1;
        }
    }

    return 0;
}
