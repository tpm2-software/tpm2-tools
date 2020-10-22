/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_ecephemeral_ctx tpm_ecephemeral_ctx;
struct tpm_ecephemeral_ctx {
    TPMI_ECC_CURVE curve_id;
    uint16_t counter;
    TPM2B_ECC_POINT *Q;
    char *commit_counter_path;
    char *ephemeral_pub_key_path;
};

static tpm_ecephemeral_ctx ctx = {
    .curve_id = TPM2_ECC_NONE,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'u':
        ctx.ephemeral_pub_key_path = value;
        break;
    case 't':
        ctx.commit_counter_path = value;
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
      { "public",   required_argument, NULL, 'u' },
      { "counter",  required_argument, NULL, 't' },
    };

    *opts = tpm2_options_new("u:t:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

    return *opts != NULL;
}

static tool_rc check_options(void) {

    if (!ctx.ephemeral_pub_key_path) {
        LOG_ERR("Invalid path specified for saving the ephemeral public key");
        return tool_rc_option_error;
    }

    if (!ctx.commit_counter_path) {
        LOG_ERR("Invalid path specified for saving the commit counter");
        return tool_rc_option_error;
    }

    if (ctx.curve_id == TPM2_ECC_NONE) {
        LOG_ERR("Invalid/ unspecified ECC curve");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc process_outputs(void) {

    FILE *fp = fopen(ctx.commit_counter_path, "wb");
    bool result = files_write_16(fp, ctx.counter);
    fclose(fp);
    if (!result) {
        LOG_ERR("Failed to write out the ECC commit count");
        return tool_rc_general_error;
    }

    result = files_save_ecc_point(ctx.Q, ctx.ephemeral_pub_key_path);
    if (!result) {
        LOG_ERR("Failed to write out the ECC pub key");
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

    // ESAPI call
    rc = tpm2_ecephemeral(ectx, ctx.curve_id, &ctx.Q, &ctx.counter);
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process outputs
    rc = process_outputs();
    Esys_Free(ctx.Q);

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("ecephemeral", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
