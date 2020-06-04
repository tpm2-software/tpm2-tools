/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

typedef struct tpm_unseal_ctx tpm_unseal_ctx;
struct tpm_unseal_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } sealkey;

    char *output_file_path;

    char *cp_hash_path;
};

static tpm_unseal_ctx ctx;

tool_rc unseal_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_SENSITIVE_DATA *output_data = NULL;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_unseal(ectx, &ctx.sealkey.object, &output_data,
            &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    tool_rc rc = tpm2_unseal(ectx, &ctx.sealkey.object, &output_data, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.output_file_path) {
        bool ret = files_save_bytes_to_file(ctx.output_file_path,
                (UINT8 *) output_data->buffer, output_data->size);
        if (!ret) {
            rc = tool_rc_general_error;
            goto out;
        }
    } else {
        bool ret = files_write_bytes(stdout, (UINT8 *) output_data->buffer,
                output_data->size);
        if (!ret) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    rc = tool_rc_success;

out:
    free(output_data);

    return rc;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    if (!ctx.sealkey.ctx_path) {
        LOG_ERR("Expected option c");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.sealkey.ctx_path,
            ctx.sealkey.auth_str, &ctx.sealkey.object, false,
            TPM2_HANDLES_FLAGS_TRANSIENT | TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid item handle authorization");
        return rc;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.sealkey.ctx_path = value;
        break;
    case 'p': {
        ctx.sealkey.auth_str = value;
    }
        break;
    case 'o':
        ctx.output_file_path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth",             required_argument, NULL, 'p' },
      { "output",           required_argument, NULL, 'o' },
      { "object-context",   required_argument, NULL, 'c' },
      { "cphash",            required_argument, NULL, 0  },
    };

    *opts = tpm2_options_new("p:o:c:", ARRAY_LEN(topts), topts, on_option, NULL,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return unseal_and_save(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.sealkey.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("unseal", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
