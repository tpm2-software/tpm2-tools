/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2017, Alibaba Group
// All rights reserved.
//
//**********************************************************************;

#include <stdbool.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

struct tpm_flush_context_ctx {
    UINT32 property;
    TPM2_HANDLE handle;
};

static struct tpm_flush_context_ctx ctx = { 0, 0 };

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

static bool flush_contexts_tpm2(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE handles[],
                          UINT32 count) {

    UINT32 i;

    for (i = 0; i < count; ++i) {
        TPM2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handles[i]));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context for %s handle 0x%x",
                    get_property_name(handles[i]), handles[i]);
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {
    (void)(value);

    switch (key) {
    case 'c':
        if (!tpm2_util_string_to_uint32(value, &ctx.handle)) {
            LOG_ERR("Could not convert handle to number, got: \"%s\"",
                    value);
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
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "context",          required_argument,  NULL, 'c' },
        { "transient-object", no_argument,        NULL, 't' },
        { "loaded-session",   no_argument,        NULL, 'l' },
        { "saved-session",    no_argument,        NULL, 's' },
    };

    *opts = tpm2_options_new("c:tls", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.property) {
        TPMS_CAPABILITY_DATA capability_data;

        TSS2_RC rc = TSS2_RETRY_EXP(Tss2_Sys_GetCapability (sapi_context,
                                     NULL,
                                     TPM2_CAP_HANDLES,
                                     ctx.property,
                                     TPM2_MAX_CAP_HANDLES,
                                     NULL,
                                     &capability_data,
                                     NULL));
        if (rc != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed to GetCapability: capability: TPM2_CAP_HANDLES");
            return 1;
        }

        TPML_HANDLE *handles = &capability_data.data.handles;
        int retval = flush_contexts_tpm2(sapi_context, handles->handle,
                                    handles->count) != true;
        if (retval) return retval;
    }

    if (ctx.handle) {
        int retval = flush_contexts_tpm2(sapi_context, &ctx.handle,
                                    1) != true;
        if (retval) return retval;
    }

    return 0;
}
