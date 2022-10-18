/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char *authValueEh;
    char *authValueSh;
    char *authValueLockout;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'E':
        ctx.authValueEh = value;
        break;
    case 'S':
        ctx.authValueSh = value;
        break;
    case 'L':
        ctx.authValueLockout = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"authValueEh",         required_argument, NULL, 'E'},
        {"authValueSh",         required_argument, NULL, 'S'},
        {"authValueLockout",    required_argument, NULL, 'L'},
    };
    return (*opts = tpm2_options_new ("E:S:L:",
        ARRAY_LEN(topts), topts, on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_Provision (fctx, ctx.authValueEh, ctx.authValueSh,
        ctx.authValueLockout);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_Provision", r);
        return 1;
    }

    return 0;
}

TSS2_TOOL_REGISTER("provision", tss2_tool_onstart, tss2_tool_onrun, NULL)
