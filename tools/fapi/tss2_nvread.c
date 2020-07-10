/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

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
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"nvPath"  , required_argument, NULL, 'p'},
        {"force" , no_argument      , NULL, 'f'},
        {"data", required_argument, NULL, 'o'},
        {"logData", required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("fo:p:l:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.nvPath) {
        fprintf (stderr, "No NV path provided, use --nvPath\n");
        return -1;
    }
    if (!ctx.data) {
        fprintf (stderr, "No file for output provided, use --data\n");
        return -1;
    }

    /* Check exclusive access to stdout */
    int count_out = 0;
    if (ctx.data && !strcmp (ctx.data, "-")) count_out +=1;
    if (ctx.logData && !strcmp (ctx.logData, "-")) count_out +=1;
    if (count_out > 1) {
        fprintf (stderr, "Only one of --data and --logData can print to - "\
        "(standard output)\n");
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

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.data, ctx.overwrite, data, data_len);
    if (r) {
        Fapi_Free (data);
        return 1;
    }

    if (ctx.logData && logData) {
        r = open_write_and_close (ctx.logData, ctx.overwrite, logData,
            strlen(logData));
        if (r) {
            Fapi_Free (data);
            Fapi_Free (logData);
            return 1;
        }
    }

    Fapi_Free (data);
    Fapi_Free (logData);

    return 0;
}

TSS2_TOOL_REGISTER("nvread", tss2_tool_onstart, tss2_tool_onrun, NULL)
