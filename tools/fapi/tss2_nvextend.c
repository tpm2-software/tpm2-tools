/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char   const *nvPath;
    char   const *data;
    char   const *logData;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'i':
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
        {"data"  , required_argument, NULL, 'i'},
        {"nvPath"  , required_argument, NULL, 'p'},
        {"logData"  , required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("i:p:l:", ARRAY_LEN(topts), topts,
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
        fprintf (stderr, "No file for input provided, use --data\n");
        return -1;
    }

    /* Check exclusive access to stdin */
    int count_in = 0;
    if (ctx.data && !strcmp (ctx.data, "-")) count_in +=1;
    if (ctx.logData && !strcmp (ctx.logData, "-")) count_in +=1;
    if (count_in > 1) {
        fprintf (stderr, "Only one of --data and --logData can read from - "\
        "(standard input)\n");
        return -1;
    }

    /* Read data to extend from file */
    uint8_t *data;
    size_t data_len;
    TSS2_RC r = open_read_and_close (ctx.data, (void**)&data, &data_len);
    if (r){
        return 1;
    }

    char *logData = NULL;
    if (ctx.logData){
        TSS2_RC r = open_read_and_close (ctx.logData, (void**)&logData, 0);
        if (r){
            free (data);
            return 1;
        }
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_NvExtend(fctx, ctx.nvPath, data, data_len, logData);
    if (r != TSS2_RC_SUCCESS){
        free (data);
        free (logData);
        LOG_PERR("Fapi_NvExtend", r);
        return 1;
    }
    free (data);
    free (logData);

    return 0;
}

TSS2_TOOL_REGISTER("nvextend", tss2_tool_onstart, tss2_tool_onrun, NULL)
