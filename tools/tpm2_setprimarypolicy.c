/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

typedef struct tpm_setprimarypolicy_ctx tpm_setprimarypolicy_ctx;
struct tpm_setprimarypolicy_ctx {
    //Input
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } hierarchy;

    const char *policy_path;

    TPMI_ALG_HASH hash_algorithm;

    char *cp_hash_path;
};

static tpm_setprimarypolicy_ctx ctx = {
    .hash_algorithm = TPM2_ALG_NULL,
};

static bool set_digest_algorithm(char *value) {

    ctx.hash_algorithm = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
    if (ctx.hash_algorithm == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert to number or lookup algorithm, got: "
                "\"%s\"", value);
        return false;
    }
    return true;
}

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'C':
        ctx.hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.hierarchy.auth_str = value;
        break;
    case 'L':
        ctx.policy_path = value;
        break;
    case 'g':
        result = set_digest_algorithm(value);
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "hierarchy",      required_argument, NULL, 'C' },
        { "auth",           required_argument, NULL, 'P' },
        { "policy",         required_argument, NULL, 'L' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "cphash",         required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:P:L:g:", ARRAY_LEN(topts), topts,
        on_option, NULL, 0);

    return *opts != NULL;
}

static bool is_input_options_args_valid(void) {

    if (!ctx.hierarchy.ctx_path) {
        LOG_ERR("Must specify the hierarchy '-C'.");
        return false;
    }

    bool result = true;
    if (ctx.policy_path) {
        unsigned long file_size = 0;
        result = files_get_file_size_path(ctx.policy_path, &file_size);
        if (!result || file_size == 0) {
            result = false;
        }
    }

    if (ctx.cp_hash_path) {
        LOG_WARN("Calculating cpHash. Exiting without setting primary policy.");
    }

    return result;
}

static tool_rc process_setprimarypolicy_input(ESYS_CONTEXT *ectx,
    TPM2B_DIGEST **auth_policy) {

    /*
     * Load hierarchy handle and auth
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.hierarchy.ctx_path,
            ctx.hierarchy.auth_str, &ctx.hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O|TPM2_HANDLE_FLAGS_P|TPM2_HANDLE_FLAGS_E|
            TPM2_HANDLE_FLAGS_L);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * Load policy digest if one is specified
     */
    if (ctx.policy_path) {

        *auth_policy = malloc(UINT16_MAX + sizeof(uint16_t));
        if (!*auth_policy) {
            LOG_ERR("oom");
            return tool_rc_general_error;
        }

        (*auth_policy)->size = UINT16_MAX;
        bool result = files_load_bytes_from_path(ctx.policy_path,
                (*auth_policy)->buffer, &((*auth_policy)->size));
        if (!result) {
            LOG_ERR("Failed loading policy digest from path");
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    bool result = is_input_options_args_valid();
    if (!result) {
        return tool_rc_option_error;
    }

    //Input
    TPM2B_DIGEST *auth_policy = NULL;
    tool_rc rc = process_setprimarypolicy_input(ectx, &auth_policy);
    if (rc != tool_rc_success) {
        return rc;
    }

    //ESAPI call
    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        rc = tpm2_setprimarypolicy(ectx, &ctx.hierarchy.object, auth_policy,
        ctx.hash_algorithm, &cp_hash);
        if (rc != tool_rc_success) {
            goto out;
        }

        result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        goto out;
    }
    rc = tpm2_setprimarypolicy(ectx, &ctx.hierarchy.object, auth_policy,
        ctx.hash_algorithm, NULL);
out:
    free(auth_policy);
    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    return tpm2_session_close(&ctx.hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("setprimarypolicy", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
