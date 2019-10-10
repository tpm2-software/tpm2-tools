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
    char const *nvPath;
    char const *data;
    char const *logData;
    bool        overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'o':
        ctx.data = value;
        break;
    case 'p':
        ctx.nvPath = value;
        break;
    case 'l':
        ctx.logData = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"nvPath"  , required_argument, NULL, 'p'},
        {"force" , no_argument      , NULL, 'f'},
        {"data", required_argument, NULL, 'o'},
        {"logData", required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("f:o:p:l:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.nvPath) {
        fprintf (stderr, "No NV path provided, use --nvPath\n");
        return -1;
    }
    if (!ctx.data) {
        fprintf (stderr, "No file for output provided, use --data\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *data;
    size_t data_len;
    char *logData = NULL;
    TSS2_RC r = Fapi_NvRead(fctx, ctx.nvPath, &data, &data_len, &logData);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_NvRead", r);
        return 1;
    }
    else {
        /* Write returned data to file(s) */
        r = open_write_and_close (ctx.data, ctx.overwrite, data, data_len);
        if (r){
            LOG_PERR ("open_write_and_close data", r);
            return 1;
        }
        if (logData){
            r = open_write_and_close (ctx.logData, ctx.overwrite, logData, strlen(logData));
            if (r){
                Fapi_Free (data);
                LOG_PERR ("open_write_and_close logData", r);
                return 1;
            }
            Fapi_Free (logData);
        }
        Fapi_Free (data);
    }
    return 0;
}
