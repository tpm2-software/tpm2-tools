/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *path;
    char const *x509cert;
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
        ctx.x509cert = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"force"   , no_argument      , NULL, 'f'},
        {"path"    , required_argument, NULL, 'p'},
        {"x509certData", required_argument, NULL, 'o'}
    };
    return (*opts = tpm2_options_new ("f:p:o:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path missing, use --path\n");
        return -1;
    }
    if (!ctx.x509cert) {
        fprintf (stderr, "x509certData missing, use --x509certData\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    char *x509certData;
    TSS2_RC r = Fapi_GetCertificate (fctx, ctx.path, &x509certData);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetCertificate", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.x509cert, ctx.overwrite, x509certData,
        strlen(x509certData));
    if (r){
        LOG_PERR ("open_read_and_close x509certData", r);
        Fapi_Free (x509certData);
        return 1;
    }
    Fapi_Free (x509certData);

    return 0;
}
