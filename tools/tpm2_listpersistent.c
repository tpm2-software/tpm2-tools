//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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
#include <ctype.h>

#include <sapi/tpm20.h>


#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_listpersistent_context tpm_listpersistent_context;
struct tpm_listpersistent_context {
    TPMI_ALG_HASH nameAlg;
    TPMI_ALG_PUBLIC type;
};

static tpm_listpersistent_context ctx = {
    .nameAlg = TPM2_ALG_NULL,
    .type = TPM2_ALG_NULL,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value);
        if(ctx.nameAlg == TPM2_ALG_ERROR ||
           !tpm2_alg_util_is_hash_alg(ctx.nameAlg)) {
            LOG_ERR("Invalid hash algorithm, got \"%s\"", value);
            return false;
        }
        break;
    case 'G':
        ctx.type = tpm2_alg_util_from_optarg(value);
        if(ctx.type == TPM2_ALG_ERROR ||
           tpm2_alg_util_is_hash_alg(ctx.type)) {
            LOG_ERR("Invalid key algorithm, got \"%s\"", value);
            return false;
        }
    }

    return true;
}

static int read_public(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT objectHandle, TPM2B_PUBLIC *outPublic) {

    UINT32 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = TSS2_RETRY_EXP(
               Tss2_Sys_ReadPublic(sapi_context, objectHandle, NULL, outPublic,
                       &name, &qualifiedName, &sessionsDataOut)
           );
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ReadPublic, rval);
        return -1;
    }

    return 0;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        {"halg", required_argument, NULL, 'g'},
        {"kalg", required_argument, NULL, 'G'},
    };

    *opts = tpm2_options_new("g:G:", ARRAY_LEN(topts), topts, on_option, NULL,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    UINT32 rval;

    UINT32 property = tpm2_util_endian_swap_32(TPM2_HT_PERSISTENT);
    rval = TSS2_RETRY_EXP(
                Tss2_Sys_GetCapability(sapi_context, NULL, TPM2_CAP_HANDLES,
                        property, TPM2_PT_TPM2_HR_PERSISTENT, &moreData,
                        &capabilityData, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_GetCapability, rval);
        return 1;
    }

    UINT32 i;
    for (i = 0; i < capabilityData.data.handles.count; i++) {
        TPM2B_PUBLIC outPublic = TPM2B_EMPTY_INIT;
        TPM2_HANDLE objectHandle = capabilityData.data.handles.handle[i];
        if (read_public(sapi_context, objectHandle, &outPublic)) {
            return 2;
        }

        TPMI_ALG_PUBLIC type = outPublic.publicArea.type;
        TPMI_ALG_HASH nameAlg = outPublic.publicArea.nameAlg;
        if ((ctx.type != TPM2_ALG_NULL && ctx.type != type)
                || (ctx.nameAlg != TPM2_ALG_NULL && ctx.nameAlg != nameAlg)) {
            /* Skip, filter me out */
            continue;
        }

        char *attrs = tpm2_attr_util_obj_attrtostr(
                outPublic.publicArea.objectAttributes);
        char *attrbuf = attrs;

        /*
         * tmp must be declared at this scope for possible use in tpm2_tool_output when attrs
         * is null.
         */
        char tmp[11]; /* UINT32 in hex (8) + "0x" + '\0' */
        if (!attrs) {
            LOG_WARN(
                    "Could not convert objectAttributes, converting to hex output");
            snprintf(tmp, sizeof(tmp), "0x%X",
                    outPublic.publicArea.objectAttributes);
            attrbuf = tmp;
        }

        tpm2_tool_output(
                "- { persistent-handle: 0x%X, key-alg: %s, hash-alg: %s, object-attr: %s }\n",
                objectHandle, tpm2_alg_util_algtostr(type),
                tpm2_alg_util_algtostr(nameAlg), attrbuf);
        free(attrs);
    }

    return 0;
}
