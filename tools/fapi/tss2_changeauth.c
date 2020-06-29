/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed to conditionally free variable authValue */
static bool has_asked_for_password = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char *entityPath;
    char *authValue;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'a':
        ctx.authValue = value;
        break;
    case 'p':
        ctx.entityPath = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"authValue",  required_argument, NULL, 'a'},
        {"entityPath", required_argument, NULL, 'p'}
    };
    return (*opts = tpm2_options_new ("a:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.entityPath) {
        fprintf (stderr, "No entity path provided, use --entityPath\n");
        return -1;
    }

    /* If no authValue was given, prompt the user interactively */
    if (!ctx.authValue) {
        ctx.authValue = ask_for_password ();
        has_asked_for_password = true;
        if (!ctx.authValue){
            return 1; /* User entered two different passwords */
        }
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_ChangeAuth(fctx, ctx.entityPath, ctx.authValue);
    if (r != TSS2_RC_SUCCESS) {
        if(has_asked_for_password){
            free (ctx.authValue);
        }
        LOG_PERR ("Fapi_ChangeAuth", r);
        return 1;
    }

    if(has_asked_for_password){
        free (ctx.authValue);
    }

    return 0;
}

TSS2_TOOL_REGISTER("changeauth", tss2_tool_onstart, tss2_tool_onrun, NULL)
