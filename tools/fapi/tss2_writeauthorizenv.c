/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *nvPath;
    char const *policyPath;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'p':
        ctx.nvPath = value;
        break;
    case 'P':
        ctx.policyPath = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"nvPath"  , required_argument, NULL, 'p'},
        {"policyPath"  , required_argument, NULL, 'P'}
    };
    return (*opts = tpm2_options_new ("p:P:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.nvPath) {
        fprintf (stderr, "No NV path provided, use --nvPath\n");
        return -1;
    }
    if (!ctx.policyPath) {
        fprintf (stderr, "No policy path provided, use --policyPath\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_WriteAuthorizeNv(fctx, ctx.nvPath, ctx.policyPath);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_WriteAuthorizeNv", r);
        return 1;
    }

    return 0;
}

TSS2_TOOL_REGISTER("writeauthorizenv", tss2_tool_onstart, tss2_tool_onrun, NULL)
