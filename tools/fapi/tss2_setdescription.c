/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *path;
    char const *description;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'i':
        if (value && strlen (value) > 1023) {
            fprintf (stderr, "The description can be at most 1023 octets\n");
            return false;
        }
        ctx.description = value;
        break;
    case 'p':
        ctx.path = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"description", required_argument, NULL, 'i'},
        {"path"       , required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("i:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path is missing, use --path\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_SetDescription (fctx, ctx.path, ctx.description);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_SetDescription", r);
        return 1;
    }
    return 0;
}

TSS2_TOOL_REGISTER("setdescription", tss2_tool_onstart, tss2_tool_onrun, NULL)
