/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char *path;
    char *jsonPolicy;
    bool overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'o':
        ctx.jsonPolicy = value;
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
        {"force",       no_argument      , NULL, 'f'},
        {"path",        required_argument, NULL, 'p'},
        {"jsonPolicy",  required_argument, NULL, 'o'},

    };
    return (*opts = tpm2_options_new ("fo:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path parameter is missing, pass --path\n");
        return -1;
    }
    if (!ctx.jsonPolicy) {
        fprintf (stderr, "parameter jsonPolicy is missing, pass --jsonPolicy\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    char *jsonPolicy;
    TSS2_RC r = Fapi_ExportPolicy (fctx, ctx.path, &jsonPolicy);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_PolicyExport", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.jsonPolicy, ctx.overwrite, jsonPolicy,
        strlen(jsonPolicy));
    if (r){
        Fapi_Free (jsonPolicy);
        return 1;
    }

    Fapi_Free (jsonPolicy);
    return 0;
}

TSS2_TOOL_REGISTER("exportpolicy", tss2_tool_onstart, tss2_tool_onrun, NULL)
