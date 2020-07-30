/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed to conditionally free variable authValue */
static bool has_asked_for_password = false;

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
static bool tss2_tool_onstart(tpm2_options **opts) {
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
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.nvPath) {
        fprintf (stderr, "No NV path provided, use --path\n");
        return -1;
    }

    uint32_t size = 0;
    if (!ctx.size) {
        /* ctx.size is allowed to be zero if type is bitfield, pcr or
         * counter
         */
        if (!ctx.nvTemplate || !(strstr(ctx.nvTemplate, "bitfield") ||
            strstr(ctx.nvTemplate, "pcr") || strstr(ctx.nvTemplate, "counter"))) {
            fprintf (stderr, "Error: Either provide a type of \"bitfield\", "\
                "pcr\" or \"counter\" with --type or provide a size > 0 with "\
                "--size.\n");
            return -1;
        }
    }
    else {
        size = ctx.size;
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
    TSS2_RC r = Fapi_CreateNv(fctx, ctx.nvPath, ctx.nvTemplate,
        size, ctx.policyPath, ctx.authValue);
    if (r != TSS2_RC_SUCCESS){
        if(has_asked_for_password){
            free (ctx.authValue);
        }
        LOG_PERR ("Fapi_CreateNv", r);
        return 1;
    }

    if(has_asked_for_password){
        free (ctx.authValue);
    }

    return 0;
}

TSS2_TOOL_REGISTER("createnv", tss2_tool_onstart, tss2_tool_onrun, NULL)
