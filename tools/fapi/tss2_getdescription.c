/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *path;
    char const *description;
    bool        overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'p':
        ctx.path = value;
        break;
    case 'o':
        ctx.description = value;
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path"        , required_argument, NULL, 'p'},
        {"description" , required_argument, NULL, 'o'},
        {"force"       , no_argument      , NULL, 'f'},
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
    if (!ctx.description) {
        fprintf (stderr, "description is missing, use --description\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    char *description;
    TSS2_RC r = Fapi_GetDescription (fctx, ctx.path, &description);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetDescription", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.description, ctx.overwrite, description,
        strlen(description));
    if (r){
        Fapi_Free (description);
        return 1;
    }
    Fapi_Free (description);

    return 0;
}

TSS2_TOOL_REGISTER("getdescription", tss2_tool_onstart, tss2_tool_onrun, NULL)
