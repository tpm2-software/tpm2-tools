/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_capability.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    TPMI_RH_PROVISION hierarchy;
    TPMI_DH_PERSISTENT persist_handle;
    tpm2_loaded_object context_object;
    const char *context_arg;
    struct {
        UINT8 p : 1;
        UINT8 P : 1;
        UINT8 c : 1;
        UINT8 o : 1;
    } flags;
    char *hierarchy_auth_str;
    const char *output_arg;
};

static tpm_evictcontrol_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    .hierarchy = TPM2_RH_OWNER,
};

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            return false;
        }
        break;
    case 'p':
        result = tpm2_util_string_to_uint32(value, &ctx.persist_handle);
        if (!result) {
            LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.p = 1;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.hierarchy_auth_str = value;
        break;
    case 'c':
        ctx.context_arg = value;
        ctx.flags.c = 1;
        break;
    case 'o':
        ctx.output_arg = value;
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",      required_argument, NULL, 'a' },
      { "persistent",     required_argument, NULL, 'p' },
      { "auth-hierarchy", required_argument, NULL, 'P' },
      { "context",        required_argument, NULL, 'c' },
      { "output",         required_argument, NULL, 'o'  },
    };

    *opts = tpm2_options_new("a:p:P:c:o:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool evicted = false;

    bool result = tpm2_util_object_load(ectx, ctx.context_arg,
                &ctx.context_object);
    if (!result) {
        goto out;
    }

    /* If we loaded the object from a hex handle we need to also load the
     * associated ESYS_TR for ESAPI calls
     */
    if (!ctx.context_object.tr_handle) {
        result = tpm2_util_sys_handle_to_esys_handle(ectx,
                    ctx.context_object.handle, &ctx.context_object.tr_handle);
        if (!result) {
            goto out;
        }
    }

    /* If we load from a saved context we won't have a TPM2_HANDLE, which we
     * need to determine whether the object is persistent
     */
    if (!ctx.context_object.handle) {
        result = tpm2_util_esys_handle_to_sys_handle(ectx,
                    ctx.context_object.tr_handle, &ctx.context_object.handle);
        if (!result) {
            goto out;
        }
    }

    /* Determine whether the loaded object is already persistent */
    if (ctx.context_object.handle >> TPM2_HR_SHIFT == TPM2_HT_PERSISTENT) {
        ctx.persist_handle = ctx.context_object.handle;
        ctx.flags.p = 1;
    }

    /* If we've been given a handle or context object to persist and not an
     * explicit persistent handle to use, find an available vacant handle in
     * the persistent namespace and use that.
     */
    if (ctx.flags.c && !ctx.flags.p) {
        result = tpm2_capability_find_vacant_persistent_handle(ectx,
                    &ctx.persist_handle);
        if (!result) {
            tpm2_tool_output("Unable to find a vacant persistent handle.\n");
            goto out;
        }
        /* we searched and found a persistent handle, so mark that peristent handle valid */
        ctx.flags.p = 1;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.hierarchy_auth_str,
               &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid authorization authorization, got\"%s\"",
                ctx.hierarchy_auth_str);
            goto out;
        }
    }

    if (ctx.flags.o && !ctx.flags.p) {
        LOG_ERR("Cannot specify -o without using a persistent handle");
    }

    ESYS_TR out_tr;
    ESYS_TR hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(ctx.hierarchy);
    result = tpm2_ctx_mgmt_evictcontrol(ectx,
            hierarchy,
            &ctx.auth.session_data,
            ctx.auth.session,
            ctx.context_object.tr_handle,
            ctx.persist_handle,
            &out_tr);
    if (!result) {
        goto out;
    }


    /*
     * Only Close a TR object if it's still resident in the TPM.
     * When these handles match, evictcontrol flushed it from the TPM.
     */
    evicted = ctx.context_object.handle == ctx.persist_handle;
    tpm2_tool_output("persistent-handle: 0x%x\n", ctx.persist_handle);
    tpm2_tool_output("action: %s\n", evicted ? "evicted" : "persisted");

    if (ctx.output_arg) {
        size_t size;
        uint8_t *buffer;
        TSS2_RC rc = Esys_TR_Serialize(ectx,
                          out_tr, &buffer, &size);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_PERR(Esys_TR_Serialize, rc);
            goto out;
        }

        result = files_save_bytes_to_file(ctx.output_arg, buffer, size);
        free(buffer);
        if (!result) {
            goto out;
        }
    }

    rc = 0;

out:

    if (!evicted) {
        TSS2_RC rval = Esys_TR_Close(ectx, &out_tr);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_TR_Close, rc);
            rc = 1;
        }
    }

    result = tpm2_session_save(ectx, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
