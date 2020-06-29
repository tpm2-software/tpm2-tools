/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char *path;
    char *importData;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'i':
        ctx.importData = value;
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
        {"importData", required_argument, NULL, 'i'},
        {"path"  , required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("i:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path parameter is missing, pass --path\n");
        return -1;
    }
    if (!ctx.importData) {
        fprintf (stderr, "importData parameter is missing, pass --importData\n");
        return -1;
    }

    /* Read file to import */
    char *importData;
    TSS2_RC r = open_read_and_close (ctx.importData, (void**)&importData, NULL);
    if (r){
        return 1;
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_Import (fctx, ctx.path, importData);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR("Fapi_Import", r);
        free (importData);
        return 1;
    }

    free (importData);

    return 0;
}

TSS2_TOOL_REGISTER("import", tss2_tool_onstart, tss2_tool_onrun, NULL)
