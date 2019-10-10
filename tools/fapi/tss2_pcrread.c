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
    uint32_t        pcrIndex;
    char     const *pcrValue;
    char     const *pcrLog;
    bool            overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'o':
        ctx.pcrValue = value;
        break;
    case 'x':
        if (!tpm2_util_string_to_uint32 (value, &ctx.pcrIndex)) {
            fprintf (stderr, "The PCR index must be an integer less than "\
                "2**32-1\n");
            return false;
        }
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'l':
        ctx.pcrLog = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"pcrIndex"     , required_argument, NULL, 'x'},
        {"pcrValue"     , required_argument, NULL, 'o'},
        {"force"         , no_argument      , NULL, 'f'},
        {"pcrLog"       , required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("o:x:f:l:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.pcrIndex) {
        fprintf (stderr, "No PCR index provided, use --pcrIndex\n");
        return -1;
    }
    if (!ctx.pcrValue) {
        fprintf (stderr, "No PCR value provided, use --pcrValue\n");
        return -1;
    }
    if (!ctx.pcrLog) {
        fprintf (stderr, "No PCR log provided, use --pcrLog\n");
        return -1;
    }
    if (!strcmp (ctx.pcrLog, "-") && !strcmp (ctx.pcrValue, "-")) {
        fprintf (stderr, "Only one of --pcrLog and --pcrIndex can print to "\
            "standard output");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *pcrValue;
    size_t pcrValueSize;
    char *pcrLog;
    TSS2_RC r = Fapi_PcrRead (fctx, ctx.pcrIndex, &pcrValue, &pcrValueSize,
        &pcrLog);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_PcrRead", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.pcrValue, ctx.overwrite, pcrValue,
        pcrValueSize);
    if (r){
        LOG_PERR ("open_write_and_close pcrValue", r);
        return 1;
    }
    if (pcrLog){
        r =  open_write_and_close (ctx.pcrLog, ctx.overwrite, pcrLog, 0);
    }
    else {
        r =  open_write_and_close (ctx.pcrLog, ctx.overwrite, "", 0);
    }
    if (r){
        LOG_PERR ("open_write_and_close pcrLog", r);
        Fapi_Free (pcrValue);
        if (pcrLog){
            Fapi_Free (pcrLog);
        }
        return 1;
    }

    Fapi_Free (pcrValue);
    if (pcrLog){
        Fapi_Free (pcrLog);
    }
    return r;
}
