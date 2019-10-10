/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char *info;
    bool  overwrite;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'o':
        ctx.info = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"force"   , no_argument      , NULL, 'f'},
        /* output file */
        {"info"  , required_argument, NULL, 'o'}
    };
    return (*opts = tpm2_options_new ("f:o:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Execute FAPI command with passed arguments */
    char *info;
    TSS2_RC r = Fapi_GetInfo (fctx, &info);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetInfo", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.info, ctx.overwrite, info, 0);
    if (r) {
        LOG_PERR ("open_write_and_close", r);
        Fapi_Free (info);
        return 1;
    }

    Fapi_Free (info);
    return 0;
}
