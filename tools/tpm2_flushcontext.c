/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_capability.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_util.h"
#include "tpm2_tool.h"

struct tpm_flush_context_ctx {
    UINT32 property;
    struct {
        char *path;
    } session;
    tpm2_loaded_object context_object;
    char *context_arg;
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

static tool_rc flush_contexts_tpm2(ESYS_CONTEXT *ectx, TPM2_HANDLE handles[],
                          UINT32 count) {

    UINT32 i;

    for (i = 0; i < count; ++i) {

        ESYS_TR handle;
        bool ok = tpm2_util_sys_handle_to_esys_handle(ectx, handles[i],
                    &handle);
        if (!ok) {
            return tool_rc_general_error;
        }

        TPM2_RC rval = Esys_FlushContext(ectx, handle);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed Flush Context for %s handle 0x%x",
                    get_property_name(handles[i]), handles[i]);
            LOG_PERR(Esys_FlushContext, rval);
            return tool_rc_from_tpm(rval);
        }
    }

    return tool_rc_success;
}

static bool flush_contexts_tr(ESYS_CONTEXT *ectx, ESYS_TR handles[],
                UINT32 count) {

    UINT32 i;

    for (i = 0; i < count; ++i) {
        TPM2_RC rval = Esys_FlushContext(ectx, handles[i]);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_FlushContext, rval);
            return tool_rc_from_tpm(rval);
        }
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {


    switch (key) {
    case 'c':
        ctx.context_arg = value;
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
        { "context",          required_argument,  NULL, 'c' },
        { "transient-object", no_argument,        NULL, 't' },
        { "loaded-session",   no_argument,        NULL, 'l' },
        { "saved-session",    no_argument,        NULL, 's' },
        { "session",          required_argument,  NULL, 'S' },
    };

    *opts = tpm2_options_new("c:tlsS:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.property) {
        TPMS_CAPABILITY_DATA *capability_data;
        bool ok = tpm2_capability_get(ectx, TPM2_CAP_HANDLES, ctx.property,
                TPM2_MAX_CAP_HANDLES, &capability_data);
        if (!ok) {
            return tool_rc_general_error;
        }

        TPML_HANDLE *handles = &capability_data->data.handles;
        tool_rc rc = flush_contexts_tpm2(ectx, handles->handle,
                                    handles->count);
        free(capability_data);
        return rc;
    }

    /* handle from a session file */
    if (ctx.session.path) {
        tpm2_session *s = NULL;
        tool_rc rc = tpm2_session_restore(ectx, ctx.session.path, true, &s);
        if (rc != tool_rc_success) {
            return rc;
        }

        tpm2_session_close(&s);

        return tool_rc_success;
    }

    tool_rc rc = tpm2_util_object_load(ectx, ctx.context_arg,
                &ctx.context_object);
    if (rc != tool_rc_success) {
        return rc;
    }

    return flush_contexts_tr(ectx, &ctx.context_object.tr_handle, 1);
}
