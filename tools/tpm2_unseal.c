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

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hash.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm_unseal_ctx tpm_unseal_ctx;
struct tpm_unseal_ctx {
    struct {
        const char *auth_str;
        tpm2_session *session;
    } parent;
    char *outFilePath;
    char *raw_pcrs_file;
    char *session_file;
    TPML_PCR_SELECTION pcr_selection;
    const char *context_arg;
    tpm2_loaded_object context_object;
    struct {
        UINT8 L : 1;
    } flags;
};

static tpm_unseal_ctx ctx;

bool unseal_and_save(ESYS_CONTEXT *ectx) {

    bool ret = false;
    TPM2B_SENSITIVE_DATA *outData = NULL;

    TSS2_RC rval;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.context_object.tr_handle,
                            ctx.parent.session);
    if (shandle1 == ESYS_TR_NONE) {
        ret = false;
        goto out;
    }

    rval = Esys_Unseal(ectx, ctx.context_object.tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &outData);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Unseal, rval);
        ret = false;
        goto out;
    }

    if (ctx.outFilePath) {
        ret = files_save_bytes_to_file(ctx.outFilePath, (UINT8 *)
                                        outData->buffer, outData->size);
    } else {
        ret = files_write_bytes(stdout, (UINT8 *) outData->buffer,
                                 outData->size);
    }

out:
    free(outData);

    return ret;
}

static bool start_auth_session(ESYS_CONTEXT *ectx) {

    tpm2_session_data *session_data =
            tpm2_session_data_new(TPM2_SE_POLICY);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    ctx.parent.session = tpm2_session_new(ectx,
            session_data);
    if (!ctx.parent.session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    bool result = tpm2_policy_build_pcr(ectx, ctx.parent.session,
                    ctx.raw_pcrs_file, &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build a pcr policy");
        return false;
    }

    return true;
}

static bool init(ESYS_CONTEXT *ectx) {

    if (!ctx.context_arg) {
        LOG_ERR("Expected option c");
        return false;
    }

    bool result = tpm2_util_object_load(ectx, ctx.context_arg,
                                &ctx.context_object);
    if (!result) {
        return false;
    }

    if (ctx.flags.L) {
        return start_auth_session(ectx);
    } else {
        result = tpm2_auth_util_from_optarg(ectx, ctx.parent.auth_str,
                &ctx.parent.session, false);
        if (!result) {
            LOG_ERR("Invalid item handle authorization, got\"%s\"", ctx.parent.auth_str);
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'p': {
        ctx.parent.auth_str = value;
    }
        break;
    case 'o':
        ctx.outFilePath = value;
        break;
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth-key",             required_argument, NULL, 'p' },
      { "out-file",             required_argument, NULL, 'o' },
      { "context-object",       required_argument, NULL, 'c' },
      { "set-list",             required_argument, NULL, 'L' },
      { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("p:o:c:L:F:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init(ectx);
    if (!result) {
        goto out;
    }

    result = unseal_and_save(ectx);
    if (!result) {
        LOG_ERR("Unseal failed!");
        goto out;
    }

    rc = 0;
out:

    if (ctx.flags.L) {
        /*
         * Only flush sessions started internally by the tool.
         */
        ESYS_TR handle = tpm2_session_get_handle(ctx.parent.session);
        TSS2_RC rval = Esys_FlushContext(ectx, handle);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_FlushContext, rval);
            rc = 1;
        }
    } else {
        result = tpm2_session_save(ectx, ctx.parent.session, NULL);
        if (!result) {
            rc = 1;
        }
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.parent.session);
}
