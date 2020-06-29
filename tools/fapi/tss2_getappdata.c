/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char const *data;
    char const *path;
    bool        overwrite;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'o':
        ctx.data = value;
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.path = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path", required_argument, NULL, 'p'},
        {"appData", required_argument, NULL, 'o'},
        {"force" , no_argument, NULL, 'f'},

    };
    return (*opts = tpm2_options_new ("o:fp:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path is missing, use --path\n");
        return -1;
    }

    /* Initialize return variables */
    uint8_t *appData;
    size_t appDataSize;

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_GetAppData (fctx, ctx.path, &appData, &appDataSize);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetAppData", r);
        return 1;
    }

    /* Write returned data to file(s) */
    if (appData && ctx.data) {
        r = open_write_and_close (ctx.data, ctx.overwrite, appData,
            appDataSize);
        if (r != TSS2_RC_SUCCESS) {
            return 1;
        }
    }

   /* Free allocated variables */
    Fapi_Free (appData);
    return 0;
}

TSS2_TOOL_REGISTER("getappdata", tss2_tool_onstart, tss2_tool_onrun, NULL)
