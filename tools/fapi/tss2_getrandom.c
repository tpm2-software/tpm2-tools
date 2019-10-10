/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    size_t  numBytes;
    char   *filename;
    bool    overwrite;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'n': {
        /*N.B. In theory size_t can be unsigned long, which is more than
         * uint32, in practice this will never happen */
        uint32_t i;
        if (!tpm2_util_string_to_uint32 (value, &i) || i == 0) {
            fprintf (stderr, "%s cannot be converted to a positive integer or "\
                "is larger than 2**32 - 1\n", value);
            return false;
        }
        ctx.numBytes = i; /* cast from uint32 to size_t */
        }
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'o':
        ctx.filename = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"numBytes", required_argument, NULL, 'n'},
        {"force"    , no_argument      , NULL, 'f'},
        /* output file */
        {"data"   , required_argument, NULL, 'o'}
    };
    return (*opts = tpm2_options_new ("f:n:o:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.filename) {
        fprintf (stderr, "No filename for data was provided, use --data\n");
        return -1;
    }
    if (!ctx.numBytes) {
        fprintf (stderr, "No amount of bytes was provided, use --numBytes\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *data;
    TSS2_RC r = Fapi_GetRandom (fctx, ctx.numBytes, &data);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetRandom", r);
        return 1;
    }

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.filename, ctx.overwrite, data,
        ctx.numBytes);
    if (r){
        LOG_PERR ("open_write_and_close output", r);
        Fapi_Free (data);
        return 1;
    }

    Fapi_Free (data);
    return r;
}
