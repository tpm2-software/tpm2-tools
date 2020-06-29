/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>

#include "tools/fapi/tss2_template.h"

/* Variable used to store passed command line parameter */
static char const *nvPath;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'p':
        nvPath = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"nvPath", required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!nvPath) {
        fprintf (stderr, "No path to the NV provided, use --nvPath\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_NvIncrement(fctx, nvPath);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR("Fapi_NV_Increment", r);
        return 1;
    }

    return 0;
}

TSS2_TOOL_REGISTER("nvincrement", tss2_tool_onstart, tss2_tool_onrun, NULL)
