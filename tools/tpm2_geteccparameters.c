/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_geteccparameters_ctx tpm_geteccparameters_ctx;
struct tpm_geteccparameters_ctx {
    TPMI_ECC_CURVE curve_id;
    const char *ecc_parameters_path;
};

static tpm_geteccparameters_ctx ctx = {
    .curve_id = TPM2_ECC_NONE,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.ecc_parameters_path = value;
        break;
    };

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify a single argument for curveID");
        return false;
    }

    bool result = true;
    TPM2B_PUBLIC algorithm = { 0 };
    if (!tpm2_alg_util_handle_ext_alg(argv[0], &algorithm)) {
        result = false;
    }

    if (algorithm.publicArea.type != TPM2_ALG_ECC) {
        result = false;
    }

    if (algorithm.publicArea.parameters.eccDetail.curveID > TPM2_ECC_NIST_P521) {
        result = false;
    }

    if (!result) {
        LOG_ERR("Invalid/unsupported ECC curve: %s", argv[0]);
        return false;
    }

    ctx.curve_id = algorithm.publicArea.parameters.eccDetail.curveID;

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "output",  required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("o:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != NULL;
}

static tool_rc check_options(void) {

    if (!ctx.ecc_parameters_path) {
        LOG_ERR("Invalid path specified for saving the ECC parameters.");
        return tool_rc_option_error;
    }

    if (ctx.curve_id == TPM2_ECC_NONE) {
        LOG_ERR("Invalid/ unspecified ECC curve");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    // Check input options and arguments
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    // ESAPI call
    TPMS_ALGORITHM_DETAIL_ECC *parameters;
    rc = tpm2_geteccparameters(ectx, ctx.curve_id, &parameters);
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process outputs
    bool result = files_save_ecc_details(parameters, ctx.ecc_parameters_path);
    if (!result) {
        LOG_ERR("Failed to write out the ECC pub key");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("geteccparameters", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
