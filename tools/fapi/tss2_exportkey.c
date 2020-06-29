/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *pathOfKeyToDuplicate;
    char const *pathToPublicKeyOfNewParent;
    char const *exportedData;
    bool        overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'e':
        ctx.pathToPublicKeyOfNewParent = value;
        break;
    case 'o':
        ctx.exportedData = value;
        break;
    case 'p':
        ctx.pathOfKeyToDuplicate = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"pathToPublicKeyOfNewParent",  required_argument, NULL, 'e'},
        {"force",                       no_argument      , NULL, 'f'},
        {"exportedData",                required_argument, NULL, 'o'},
        {"pathOfKeyToDuplicate",        required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("fe:o:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.exportedData) {
        fprintf (stderr, "exported data missing, use --output\n");
        return -1;
    }
    if (!ctx.pathOfKeyToDuplicate) {
        fprintf (stderr, "path of key to duplicate missing, use --path\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    char *exportedData;
    TSS2_RC r = Fapi_ExportKey (fctx, ctx.pathOfKeyToDuplicate,
        ctx.pathToPublicKeyOfNewParent, &exportedData);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_ExportKey", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.exportedData, ctx.overwrite, exportedData,
        strlen(exportedData));
    if (r){
        Fapi_Free (exportedData);
        return 1;
    }

    Fapi_Free (exportedData);
    return 0;
}

TSS2_TOOL_REGISTER("exportkey", tss2_tool_onstart, tss2_tool_onrun, NULL)
