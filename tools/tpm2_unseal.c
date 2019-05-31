/* SPDX-License-Identifier: BSD-3-Clause */

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
    const char *auth_str;
    tpm2_session *session;
    char *outFilePath;
    const char *context_arg;
    tpm2_loaded_object context_object;
};

static tpm_unseal_ctx ctx;

bool unseal_and_save(ESYS_CONTEXT *ectx) {

    bool ret = false;
    TPM2B_SENSITIVE_DATA *outData = NULL;

    TSS2_RC rval;

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.context_object.tr_handle,
                            ctx.session);
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

    result = tpm2_auth_util_from_optarg(ectx, ctx.auth_str,
            &ctx.session, false);
    if (!result) {
        LOG_ERR("Invalid item handle authorization, got\"%s\"", ctx.auth_str);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'p': {
        ctx.auth_str = value;
    }
        break;
    case 'o':
        ctx.outFilePath = value;
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
    };

    *opts = tpm2_options_new("p:o:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result = init(ectx);
    if (!result) {
        return tool_rc_general_error;
    }

    result = unseal_and_save(ectx);
    if (!result) {
        LOG_ERR("Unseal failed!");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}
