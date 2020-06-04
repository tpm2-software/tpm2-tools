/* SPDX-License-Identifier: BSD-3-Clause */
#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

typedef struct tpm_ecdhzgen_ctx tpm_ecdhzgen_ctx;
struct tpm_ecdhzgen_ctx {

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } ecc_key;

    const char *ecdh_pub_path;
    const char *ecdh_Z_path;

    TPM2B_ECC_POINT *Z;
    TPM2B_ECC_POINT Q;
};

static tpm_ecdhzgen_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {

        case 'c':
            ctx.ecc_key.ctx_path = value;
            break;
        case 'p':
            ctx.ecc_key.auth_str = value;
            break;
        case 'u':
            ctx.ecdh_pub_path = value;
            break;
        case 'o':
            ctx.ecdh_Z_path = value;
            break;
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "key-context", required_argument, NULL, 'c' },
      { "key-auth",    required_argument, NULL, 'p' },
      { "public",      required_argument, NULL, 'u' },
      { "output",      required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("c:p:u:o:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc check_options(void) {

    if (!ctx.ecc_key.ctx_path) {
        LOG_ERR("Specify an ecc public key handle for context");
        return tool_rc_option_error;
    }

    if (!ctx.ecdh_Z_path) {
        LOG_ERR("Specify path to save the ecdh secret or Z point");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    tool_rc  rc = tpm2_util_object_load_auth(ectx, ctx.ecc_key.ctx_path,
        ctx.ecc_key.auth_str, &ctx.ecc_key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to load object/ auth");
        return rc;
    }

    bool result = true;
    result = files_load_ecc_point(ctx.ecdh_pub_path, &ctx.Q);
    if (!result) {
        LOG_ERR("Failed to load public input ECC point Q");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    // Check input options and arguments
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process inputs
   rc = process_inputs(ectx);
   if (rc != tool_rc_success) {
       return rc;
   }

    // ESAPI call
    rc = tpm2_ecdhzgen(ectx, &ctx.ecc_key.object, &ctx.Z, &ctx.Q);
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process outputs
    bool result = files_save_ecc_point(ctx.Z, ctx.ecdh_Z_path);
    if (!result) {
        LOG_ERR("Failed to write out the public");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("ecdhzgen", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
