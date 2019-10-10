/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* needed to conditionally free variable authValue */
bool has_asked_for_password = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char     const *nvPath;
    char     const *nvTemplate;
    char           *authValue;
    uint32_t        size;
    char     const *policyPath;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'a':
        ctx.authValue = value;
        break;
    case 'P':
        ctx.policyPath = value;
        break;
    case 'p':
        ctx.nvPath = value;
        break;
    case 's':
        if (!tpm2_util_string_to_uint32 (value, &ctx.size)) {
            fprintf (stderr, "%s cannot be converted to an integer or is" \
                " larger than 2**32 - 1\n", value);
            return false;
        }
        break;
    case 't':
        ctx.nvTemplate = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path",       required_argument, NULL, 'p'},
        {"type",       required_argument, NULL, 't'},
        {"size",       required_argument, NULL, 's'},
        {"policyPath", required_argument, NULL, 'P'},
        {"authValue",  required_argument, NULL, 'a'},
    };
    return (*opts = tpm2_options_new ("P:a:p:s:t:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.policyPath) {
        ctx.policyPath = "";
    }
    if (!ctx.nvPath) {
        fprintf (stderr, "No NV path provided, use --path\n");
        return -1;
    }
    if (!ctx.nvTemplate) {
        fprintf (stderr, "No type provided, use --type\n");
        return -1;
    }

    /* If no authValue was given, prompt the user interactively */
    if (!ctx.authValue) {
        ctx.authValue = ask_for_password ();
        has_asked_for_password = true;
        if (!ctx.authValue){
            free (ctx.authValue);
            return 1; /* User entered two different passwords */
        }
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_CreateNv(fctx, ctx.nvPath, ctx.nvTemplate,
        ctx.size, ctx.policyPath, ctx.authValue);
    if (r != TSS2_RC_SUCCESS){
        if(has_asked_for_password){
            free (ctx.authValue);
        }
        LOG_PERR ("Fapi_CreateNv", r);
    }

    if(has_asked_for_password){
        free (ctx.authValue);
    }

    return r;
}
