/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed command line parameters */
static struct cxt {
    uint32_t        pcr;
    char     const *data;
    char     const *logData;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch  (key) {
    case 'x':
        if (!tpm2_util_string_to_uint32 (value, &ctx.pcr)) {
            fprintf (stderr, "%s cannot be converted to an integer or is"\
                "larger than 2**32 - 1\n", value);
            return false;
        }
        break;
    case 'i':
        ctx.data = value;
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
        {"pcr"       , required_argument, NULL, 'x'},
        {"data", required_argument, NULL, 'i'},
        {"logData", required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("x:i:l", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.pcr) {
        fprintf (stderr, "No pcr provided, use --pcr\n");
        return -1;
    }
    if (!ctx.data) {
        fprintf (stderr, "No event data provided, use --data\n");
        return -1;
    }
    if (!ctx.logData) {
        fprintf (stderr, "No log data provided, use --logData\n");
        return -1;
    }

    /* Read event data and log data from file */
    uint8_t *data;
    size_t eventDataSize;
    TSS2_RC r = open_read_and_close (ctx.data, (void**)&data,
        &eventDataSize);
    if (r){
        LOG_PERR ("open_read_and_close data", r);
        return -1;
    }
    char *logData;
    r = open_read_and_close (ctx.logData, (void**)&logData, 0);
    if (r){
        LOG_PERR ("open_read_and_close logData", r);
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_PcrExtend(fctx, ctx.pcr, data, eventDataSize, logData);
    if (r != TSS2_RC_SUCCESS){
        free (logData);
        LOG_PERR ("Fapi_PcrExtend", r);
        return 1;
    }

    Fapi_Free (data);
    free (logData);

    return 0;
}
