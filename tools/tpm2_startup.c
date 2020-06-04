/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

/*
 * Both the Microsoft and IBM TPM2 simulators require some specific setup
 * before they can be used by the SAPI. This setup is specific to the
 * simulators and is something that the low-level hardware / firmware does
 * for a discrete TPM.
 * NOTE: In the code that interacts with a TPM this can be a very ugly
 * abstraction leak.
 */
typedef struct tpm2_startup_ctx tpm2_startup_ctx;
struct tpm2_startup_ctx {
    UINT8 clear :1;
};

static tpm2_startup_ctx ctx;

static bool on_option(char key, char *value) {

    UNUSED(value);

    switch (key) {
    case 'c':
        ctx.clear = 1;
        break;
        /*no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts [] = {
        { "clear", no_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("c", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    TPM2_SU startup_type = ctx.clear ? TPM2_SU_CLEAR : TPM2_SU_STATE;

    LOG_INFO("Sending TPM_Startup command with type: %s",
            ctx.clear ? "TPM2_SU_CLEAR" : "TPM2_SU_STATE");

    return tpm2_startup(context, startup_type);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("startup", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
