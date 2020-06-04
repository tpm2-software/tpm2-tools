/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

typedef struct tpm_selftest_ctx tpm_selftest_ctx;

struct tpm_selftest_ctx {
    TPMI_YES_NO fulltest;
};

static tpm_selftest_ctx ctx;

static bool on_option(char key, char *value) {

    UNUSED(value);

    switch (key) {
    case 'f':
        ctx.fulltest = TPM2_YES;
        break;
    default:
        LOG_ERR("Invalid option.");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "fulltest", no_argument, NULL, 'f' }
    };

    ctx.fulltest = TPM2_NO;

    *opts = tpm2_options_new("f", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return tpm2_selftest(ectx, ctx.fulltest);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("selftest", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
