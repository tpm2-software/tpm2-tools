//**********************************************************************;
// Copyright (c) 2017, Alibaba Group
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

#include <inttypes.h>
#include <stdbool.h>

#include <tss2/tss2_sys.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

struct tpm_flush_context_ctx {
    UINT32 property;
    TPM2_HANDLE objectHandle;
    struct {
        char *path;
    } session;
};

static struct tpm_flush_context_ctx ctx;

static const char *get_property_name(TPM2_HANDLE handle) {

    switch (handle & TPM2_HR_RANGE_MASK) {
        case TPM2_HR_TRANSIENT:
            return "transient";
        case TPM2_HT_LOADED_SESSION << TPM2_HR_SHIFT:
            return "loaded session";
        case TPM2_HT_SAVED_SESSION << TPM2_HR_SHIFT:
            return "saved session";
    }

    return "invalid";
}

static TSS2_RC
get_capability_handles(TSS2_SYS_CONTEXT *sapi_ctx, UINT32 property,
                       TPMS_CAPABILITY_DATA *capability_data) {

    TPMI_YES_NO more_data;

    TSS2_RC rval = Tss2_Sys_GetCapability(sapi_ctx, NULL, TPM2_CAP_HANDLES, property,
                                TPM2_MAX_CAP_HANDLES, &more_data,
                                capability_data,
                                NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_GetCapability, rval);
    } else if (more_data) {
        LOG_WARN("More data to be queried: capability: 0x%x, property: "
                 "0x%x", TPM2_CAP_HANDLES, property);
    }

    return rval;
}

static bool flush_contexts(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE handles[],
                          UINT32 count) {

    UINT32 i;

    for (i = 0; i < count; ++i) {

        TPM2_RC rval = Tss2_Sys_FlushContext(sapi_context, handles[i]);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context for %s handle 0x%x",
                    get_property_name(handles[i]), handles[i]);
            LOG_PERR(Tss2_Sys_FlushContext, rval);
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'H':
        result = tpm2_util_string_to_uint32(value, &ctx.objectHandle);
        if (!result) {
            return false;
        }
        break;
    case 't':
        ctx.property = TPM2_TRANSIENT_FIRST;
        break;
    case 'l':
        ctx.property = TPM2_LOADED_SESSION_FIRST;
        break;
    case 's':
        ctx.property = TPM2_ACTIVE_SESSION_FIRST;
        break;
    case 'S':
        ctx.session.path = value;
    break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "handle",           no_argument,        NULL, 'H' },
        { "transient-object", no_argument,        NULL, 't' },
        { "loaded-session",   no_argument,        NULL, 'l' },
        { "saved-session",    no_argument,        NULL, 's' },
        { "session",          required_argument,  NULL, 'S' },
    };

    *opts = tpm2_options_new("H:tlsS:", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMS_CAPABILITY_DATA capability_data = TPMS_CAPABILITY_DATA_EMPTY_INIT;
    TPML_HANDLE *handles = &capability_data.data.handles;
    
    if (ctx.property) {
        TSS2_RC rc;

        rc = get_capability_handles(sapi_context, ctx.property, &capability_data);
        if (rc != TPM2_RC_SUCCESS) {
            return 1;
        }
    } else {

        /* handle from a session file */
        if (ctx.session.path) {
            tpm2_session *s = tpm2_session_restore(sapi_context, ctx.session.path);
            if (!s) {
                return 1;
            }

            ctx.objectHandle = tpm2_session_get_handle(s);

            tpm2_session_free(&s);
        }

        handles->handle[0] = ctx.objectHandle;
        LOG_INFO("got session handle 0x%" PRIx32, handles->handle[0]);
        handles->count = 1;
    }

    return flush_contexts(sapi_context, handles->handle,
                          handles->count) != true;
}
