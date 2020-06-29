/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *path;
    char const *data;
    bool        overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.path = value;
        break;
    case 'o':
        ctx.data = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path",    required_argument, NULL, 'p'},
        {"data",    required_argument, NULL, 'o'},
        {"force",   no_argument, NULL, 'f'}
    };
    return (*opts = tpm2_options_new ("p:o:f", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path to the sealed data missing, use --path\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *data;
    size_t size;
    TSS2_RC r = Fapi_Unseal (fctx, ctx.path, &data, &size);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_Unseal", r);
        return 1;
    }

    /* Write returned data to file(s) */
    if (ctx.data && data) {
        r = open_write_and_close (ctx.data, ctx.overwrite, data, size);
        if (r) {
            Fapi_Free (data);
            return 1;
        }
    }
    Fapi_Free (data);

    return 0;
}

TSS2_TOOL_REGISTER("unseal", tss2_tool_onstart, tss2_tool_onrun, NULL)
