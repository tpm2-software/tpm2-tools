/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed to conditionally free variable authValue */
static bool has_asked_for_password = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char const *keyPath;
    char const *keyType;
    char const *policyPath;
    char       *authValue;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'a':
        ctx.authValue = value;
        break;
    case 'p':
        ctx.keyPath = value;
        break;
    case 'P':
        ctx.policyPath = value;
        break;
    case 't':
        ctx.keyType = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path",       required_argument, NULL, 'p'},
        {"type",       required_argument, NULL, 't'},
        {"policyPath", required_argument, NULL, 'P'},
        {"authValue",  required_argument, NULL, 'a'},
    };
    return (*opts = tpm2_options_new ("a:p:P:t:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.keyPath) {
        fprintf (stderr, "key path missing, use --path\n");
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
    TSS2_RC r = Fapi_CreateKey (fctx, ctx.keyPath, ctx.keyType, ctx.policyPath,
        ctx.authValue);
    if (r != TSS2_RC_SUCCESS){
        if(has_asked_for_password){
            free (ctx.authValue);
        }
        LOG_PERR ("Fapi_CreateKey", r);
        return 1;
    }

    if(has_asked_for_password){
        free (ctx.authValue);
    }

    return 0;
}

TSS2_TOOL_REGISTER("createkey", tss2_tool_onstart, tss2_tool_onrun, NULL)
