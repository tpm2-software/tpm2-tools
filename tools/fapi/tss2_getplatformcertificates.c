/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char const *certificates;
    bool        overwrite;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'o':
        ctx.certificates = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"force",           no_argument      , NULL, 'f'},
        {"certificates",    required_argument, NULL, 'o'}
    };
    return (*opts = tpm2_options_new ("f:o:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.certificates) {
        fprintf (stderr, "certificates missing, use --certificates\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *certificates;
    size_t  certificatesSize = 0;
    TSS2_RC r = Fapi_GetPlatformCertificates (fctx, &certificates,
        &certificatesSize);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetPlatformCertificates", r);
        if (certificatesSize>0){
            Fapi_Free (certificates);
        }
        return 1;
    }

    /* Write returned data to file(s) */
    if (certificatesSize>0){
        r = open_write_and_close (ctx.certificates, ctx.overwrite,
            certificates, certificatesSize);
        if (r){
            LOG_PERR ("open_write_and_close certificates", r);
            Fapi_Free (certificates);
            return 1;
        }
        Fapi_Free (certificates);
    }

    return 0;
}
