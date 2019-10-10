/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    uint8_t const *data;
    size_t  data_size;
    char    const *path;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'i':
        ctx.data_size = strlen(value);
        ctx.data = (uint8_t*) value;
        break;
    case 'p':
        ctx.path = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"appData", required_argument, NULL, 'i'},
        {"path", required_argument, NULL, 'p'},
    };
    return (*opts = tpm2_options_new ("i:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path is missing, use --path\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_SetAppData (fctx, ctx.path, ctx.data, ctx.data_size);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_SetAppData", r);
        return 1;
    }
    return 0;
}
