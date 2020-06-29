/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    bool  overwrite;
    char *searchPath;
    char *pathList;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.searchPath = value;
        break;
    case 'o':
        ctx.pathList = value ? value : "-";
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"force"   , no_argument      , NULL, 'f'},
        {"searchPath", required_argument, NULL, 'p'},
        {"pathList",   required_argument, NULL, 'o'}
    };
    return (*opts = tpm2_options_new ("fp:o:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    (void) fctx;
    /* Execute FAPI command with passed arguments */
    char *pathList = NULL;
    TSS2_RC r = Fapi_List(fctx,
        ctx.searchPath ? ctx.searchPath : "", &pathList);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_List", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.pathList, ctx.overwrite, pathList,
        strlen(pathList));
    if (r){
        Fapi_Free (pathList);
        return 1;
    }

    Fapi_Free (pathList);
    return 0;
}

TSS2_TOOL_REGISTER("list", tss2_tool_onstart, tss2_tool_onrun, NULL)
