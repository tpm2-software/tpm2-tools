/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>

#include "tools/fapi/tss2_template.h"

static char *path;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'p':
        path = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path", required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    if (!path) {
        fprintf (stderr, "No path to the entity provided, use --path\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_Delete(fctx, path);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_Delete", r);
        return 1;
    }
    return 0;
}

TSS2_TOOL_REGISTER("delete", tss2_tool_onstart, tss2_tool_onrun, NULL)
