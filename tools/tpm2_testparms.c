/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_testparms_ctx tpm_testparms_ctx;

struct tpm_testparms_ctx {
    TPMT_PUBLIC_PARMS inputalg;
};

static tpm_testparms_ctx ctx;

static tool_rc tpm_testparms(ESYS_CONTEXT *ectx) {

    TSS2_RC rval = Esys_TestParms(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &(ctx.inputalg));
    /*
     * TODO: this is a good candidate for flatten support via Tss2_RC_Decode(rval);
     */
    if (rval != TSS2_RC_SUCCESS) {
        if ((rval & (TPM2_RC_P | TPM2_RC_1)) == (TPM2_RC_P | TPM2_RC_1)) {
            rval &= ~(TPM2_RC_P | TPM2_RC_1);
            switch (rval) {
            case TPM2_RC_CURVE:
                LOG_ERR("Specified elliptic curve is unsupported");
                break;
            case TPM2_RC_HASH:
                LOG_ERR("Specified hash is unsupported");
                break;
            case TPM2_RC_SCHEME:
                LOG_ERR("Specified signing scheme is unsupported or "
                        "incompatible");
                break;
            case TPM2_RC_KDF:
                LOG_ERR("Specified key derivation function is unsupported");
                break;
            case TPM2_RC_MGF:
                LOG_ERR("Specified mask generation function is unsupported");
                break;
            case TPM2_RC_KEY_SIZE:
                LOG_ERR("Specified key size is unsupported");
                break;
            case TPM2_RC_SYMMETRIC:
                LOG_ERR(
                        "Specified symmetric algorithm or key length is "
                        "unsupported");
                break;
            case TPM2_RC_ASYMMETRIC:
                LOG_ERR("Specified asymmetric algorithm is unsupported");
                break;
            case TPM2_RC_MODE:
                LOG_ERR("Specified symmetric mode unsupported");
                break;
            case TPM2_RC_VALUE:
            default:
                LOG_ERR("Unsupported algorithm specification");
                break;
            }
            return tool_rc_unsupported;
        }
        LOG_PERR(Esys_TestParms, rval);
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    if (argc < 1) {
        LOG_ERR("Expected one algorithm specification, got: 0");
        return false;
    }

    TPM2B_PUBLIC algorithm = { 0 };

    if (!tpm2_alg_util_handle_ext_alg(argv[0], &algorithm)) {
        LOG_ERR("Invalid or unsupported by the tool : %s", argv[0]);
        return false;
    }

    ctx.inputalg.type = algorithm.publicArea.type;
    memcpy(&ctx.inputalg.parameters, &algorithm.publicArea.parameters,
            sizeof(TPMU_PUBLIC_PARMS));
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return tpm_testparms(ectx);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("testparms", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
