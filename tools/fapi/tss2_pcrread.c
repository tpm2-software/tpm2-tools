/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    bool            pcr_set;
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
	ctx.pcr_set = true;
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
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"pcrIndex"     , required_argument, NULL, 'x'},
        {"pcrValue"     , required_argument, NULL, 'o'},
        {"force"         , no_argument      , NULL, 'f'},
        {"pcrLog"       , required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("o:x:fl:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.pcr_set) {
        fprintf (stderr, "No PCR index provided, use --pcrIndex\n");
        return -1;
    }

    /* Check exclusive access to stdout */
    int count_out = 0;
    if (ctx.pcrValue && !strcmp (ctx.pcrValue, "-")) count_out +=1;
    if (ctx.pcrLog && !strcmp (ctx.pcrLog, "-")) count_out +=1;
    if (count_out > 1) {
        fprintf (stderr, "Only one of --pcrValue and --pcrLog can print to - "\
        "(standard output)\n");
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
    if (ctx.pcrValue) {
        r = open_write_and_close (ctx.pcrValue, ctx.overwrite, pcrValue,
            pcrValueSize);
        if (r) {
            Fapi_Free (pcrLog);
            Fapi_Free (pcrValue);
            return 1;
        }
    }

    if (ctx.pcrLog) {
        r =  open_write_and_close (ctx.pcrLog, ctx.overwrite, pcrLog,
            strlen(pcrLog));
        if (r) {
            Fapi_Free (pcrLog);
            Fapi_Free (pcrValue);
            return 1;
        }
    }

    Fapi_Free (pcrLog);
    Fapi_Free (pcrValue);

    return 0;
}

TSS2_TOOL_REGISTER("pcrread", tss2_tool_onstart, tss2_tool_onrun, NULL)
