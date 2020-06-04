/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_capability.h"
#include "tpm2_options.h"

struct tpm_flush_context_ctx {
    TPM2_HANDLE property;
    char *context_arg;
    unsigned encountered_option;
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
        tool_rc rc = tpm2_util_sys_handle_to_esys_handle(ectx, handles[i],
                &handle);
        if (rc != tool_rc_success) {
            return rc;
        }

        rc = tpm2_flush_context(ectx, handle);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed Flush Context for %s handle 0x%x",
                    get_property_name(handles[i]), handles[i]);
            return rc;
        }
    }

    return tool_rc_success;
}

static bool flush_contexts_tr(ESYS_CONTEXT *ectx, ESYS_TR handles[],
        UINT32 count) {

    UINT32 i;

    for (i = 0; i < count; ++i) {
        tool_rc rc = tpm2_flush_context(ectx, handles[i]);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {
    UNUSED(value);

    if (ctx.encountered_option) {
        LOG_ERR("Options -t, -l and -s are mutually exclusive");
        return false;
    }

    ctx.encountered_option = true;

    switch (key) {
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

static bool on_arg(int argc, char *argv[]) {

    if (ctx.encountered_option && argc != 0) {
        LOG_ERR("Options are mutually exclusive of an argument");
        return false;
    }

    ctx.context_arg = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "transient-object", no_argument, NULL, 't' },
        { "loaded-session",   no_argument, NULL, 'l' },
        { "saved-session",    no_argument, NULL, 's' },
    };

    *opts = tpm2_options_new("tls", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (ctx.property) {
        TPMS_CAPABILITY_DATA *capability_data;
        tool_rc rc = tpm2_capability_get(ectx, TPM2_CAP_HANDLES, ctx.property,
                TPM2_MAX_CAP_HANDLES, &capability_data);
        if (rc != tool_rc_success) {
            return rc;
        }

        TPML_HANDLE *handles = &capability_data->data.handles;
        rc = flush_contexts_tpm2(ectx, handles->handle, handles->count);
        free(capability_data);
        return rc;
    }

    if (!ctx.context_arg) {
        LOG_ERR("Specify options to evict handles or a session context.");
        return tool_rc_option_error;
    }

    TPM2_HANDLE handle;
    bool result = tpm2_util_string_to_uint32(ctx.context_arg, &handle);
    if (!result) {
        /* hmm not a handle, try a session */
        tpm2_session *s = NULL;
        tool_rc rc = tpm2_session_restore(ectx, ctx.context_arg, true, &s);
        if (rc != tool_rc_success) {
            return rc;
        }

        tpm2_session_close(&s);

        return tool_rc_success;
    }

    /* its a handle, call flush */
    ESYS_TR tr_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_util_sys_handle_to_esys_handle(ectx, handle, &tr_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    return flush_contexts_tr(ectx, &tr_handle, 1);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("flushcontext", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
