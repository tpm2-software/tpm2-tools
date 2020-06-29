/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char     const *path;
    uint64_t        bitmap;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'i': {
        uint64_t i;
        if (!tpm2_util_string_to_uint64 (value, &i) || i == 0) {
            fprintf (stderr, "%s cannot be converted to a positive integer or "\
                "is larger than 2**64 - 1\n", value);
            return false;
        }
        ctx.bitmap = i; /* cast from uint32 to size_t */
        }
        break;
    case 'p':
        ctx.path = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"bitmap", required_argument, NULL, 'i'},
        {"nvPath"    , required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("i:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "No path to the NV provided, use --nvPath\n");
        return -1;
    }
    if (!ctx.bitmap) {
        fprintf (stderr, "No bits provided, use --bitmap [0x...]\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_NvSetBits(fctx, ctx.path, ctx.bitmap);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_NvSetBits", r);
        return 1;
    }

    return 0;
}

TSS2_TOOL_REGISTER("nvsetbits", tss2_tool_onstart, tss2_tool_onrun, NULL)
