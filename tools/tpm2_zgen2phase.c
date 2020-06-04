/* SPDX-License-Identifier: BSD-3-Clause */
#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_ecdhzgen_ctx tpm_ecdhzgen_ctx;
struct tpm_ecdhzgen_ctx {

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } ecc_key;

    const char *output_z1_path;
    const char *output_z2_path;
    TPM2B_ECC_POINT *Z1;
    TPM2B_ECC_POINT *Z2;

    const char *static_public_path;
    const char *ephemeral_public_path;
    TPM2B_ECC_POINT Q1;
    TPM2B_ECC_POINT Q2;

    UINT16 commit_counter;
    TPMI_ECC_KEY_EXCHANGE keyexchange_scheme;
};

static tpm_ecdhzgen_ctx ctx = {
    .keyexchange_scheme = TPM2_ALG_ECDH,
};

static bool on_option(char key, char *value) {

    bool result = true;
    switch (key) {
        case 'c':
            ctx.ecc_key.ctx_path = value;
            break;
        case 'p':
            ctx.ecc_key.auth_str = value;
            break;
        case 's':
            ctx.keyexchange_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
            break;
        case 't':
            result = tpm2_util_string_to_uint16(value, &ctx.commit_counter);
            if (!result) {
                LOG_ERR("Could not convert commit counter to number, got: \"%s\"",
                        value);
                return false;
            }
            break;
        case 0:
            ctx.static_public_path = value;
            break;
        case 1:
            ctx.ephemeral_public_path = value;
            break;
        case 2:
            ctx.output_z1_path = value;
            break;
        case 3:
            ctx.output_z2_path = value;
            break;
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "key-context",      required_argument, NULL, 'c' },
      { "key-auth",         required_argument, NULL, 'p' },
      { "scheme",           required_argument, NULL, 's' },
      { "counter",          required_argument, NULL, 't' },
      { "static-public",    required_argument, NULL,  0  },
      { "ephemeral-public", required_argument, NULL,  1  },
      { "output-Z1",        required_argument, NULL,  2  },
      { "output-Z2",        required_argument, NULL,  3  },
    };

    *opts = tpm2_options_new("c:p:s:t:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc check_options(void) {

    if (ctx.keyexchange_scheme != TPM2_ALG_ECDH &&
        ctx.keyexchange_scheme != TPM2_ALG_ECMQV &&
        ctx.keyexchange_scheme != TPM2_ALG_SM2) {
            LOG_ERR("Unknown signing scheme");
            return tool_rc_general_error;
    }

    if (!ctx.ecc_key.ctx_path) {
        LOG_ERR("Specify an ecc key handle for context");
        return tool_rc_option_error;
    }

    if (!ctx.static_public_path) {
        LOG_ERR("Specify path to read the static public data from.");
        return tool_rc_option_error;
    }

    if (!ctx.ephemeral_public_path) {
        LOG_ERR("Specify path to read the ephemeral public data from.");
        return tool_rc_option_error;
    }

    if (!ctx.output_z1_path) {
        LOG_ERR("Specify path to save the Z1 data.");
        return tool_rc_option_error;
    }

    if (!ctx.output_z2_path) {
        LOG_ERR("Specify path to save the Z2 data.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.ecc_key.ctx_path,
        ctx.ecc_key.auth_str, &ctx.ecc_key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = true;
    result = files_load_ecc_point(ctx.static_public_path, &ctx.Q1);
    if (!result) {
        LOG_ERR("Failed to load static public input ECC point Q1");
        return tool_rc_general_error;
    }

    result = files_load_ecc_point(ctx.ephemeral_public_path, &ctx.Q2);
    if (!result) {
        LOG_ERR("Failed to load static public input ECC point Q2");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc process_outputs(void) {

    bool result = files_save_ecc_point(ctx.Z1, ctx.output_z1_path);
    if (!result) {
        LOG_ERR("Failed to write out the ECC point Z1");
        return tool_rc_general_error;
    }

    result = files_save_ecc_point(ctx.Z2, ctx.output_z2_path);
    if (!result) {
        LOG_ERR("Failed to write out the ECC point Z2");
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
    rc = tpm2_zgen2phase(ectx, &ctx.ecc_key.object, &ctx.Q1, &ctx.Q2, &ctx.Z1,
    &ctx.Z2, ctx.keyexchange_scheme, ctx.commit_counter);
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process ouputs
    rc = process_outputs();

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("zgen2phase", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
