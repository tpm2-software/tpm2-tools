/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *path;
    char const *x509cert;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'p':
        ctx.path = value;
        break;
    case 'i':
        ctx.x509cert = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path"    , required_argument, NULL, 'p'},
        {"x509certData", required_argument, NULL, 'i'}
    };
    return (*opts = tpm2_options_new ("p:i", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path missing, use --path\n");
        return -1;
    }

    /* Read x509 certificate from file */
    TSS2_RC r;
    char* x509certData = NULL;
    size_t x509certSize;
    if (ctx.x509cert) {
        r = open_read_and_close (ctx.x509cert, (void**)&x509certData,
            &x509certSize);
        if (r) {
            return 1;
        }
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_SetCertificate (fctx, ctx.path, x509certData);
    if (r != TSS2_RC_SUCCESS){
        free (x509certData);
        LOG_PERR("Fapi_SetCertificate", r);
        return 1;
    }
    free (x509certData);
    return 0;
}

TSS2_TOOL_REGISTER("setcertificate", tss2_tool_onstart, tss2_tool_onrun, NULL)
