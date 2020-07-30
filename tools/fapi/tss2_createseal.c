/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed to conditionally free variable authValue */
static bool has_asked_for_password = false;

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *keyPath;
    char const *keyType;
    char const *policyPath;
    char       *authValue;
    char const *data;
    uint32_t        size;
} ctx;

/* Parse command line parameters */
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
    case 'i':
        ctx.data = value;
        break;
    case 's':
        if (!tpm2_util_string_to_uint32 (value, &ctx.size)) {
            fprintf (stderr, "%s cannot be converted to an integer or is" \
                " larger than 2**32 - 1\n", value);
            return false;
        }
        if (ctx.size == 0) {
            LOG_ERR("Size parameter must be larger than 0\n");
            return false;
        }
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path",       required_argument, NULL, 'p'},
        {"type",       required_argument, NULL, 't'},
        {"policyPath", required_argument, NULL, 'P'},
        {"authValue",  required_argument, NULL, 'a'},
        {"data",       required_argument, NULL, 'i'},
        {"size",       required_argument, NULL, 's'}
    };
    return (*opts = tpm2_options_new ("a:p:P:t:i:s:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.keyPath) {
        fprintf (stderr, "key path missing, use --path\n");
        return -1;
    }

    if (!ctx.data && !ctx.size) {
        fprintf (stderr, "One of --data or --size "\
        "must be used\n");
        return -1;
    }

    if (ctx.data && ctx.size) {
        fprintf (stderr, "Only one of --data and --size "\
        "can be used\n");
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

    /* Read data file */
    TSS2_RC r;
    uint8_t* data = NULL;
    size_t dataSize = 0;
    if (ctx.data) {
        r = open_read_and_close (ctx.data, (void**)&data, &dataSize);
        if (r) {
            return 1;
        }
    }
    else {
        if (ctx.size) {
            dataSize = ctx.size;
        }
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_CreateSeal (fctx, ctx.keyPath, ctx.keyType,
        dataSize, ctx.policyPath, ctx.authValue, data);
    if (r != TSS2_RC_SUCCESS){
        if(has_asked_for_password){
            free (ctx.authValue);
        }
        free (data);
        LOG_PERR ("Fapi_CreateSeal", r);
        return 1;
    }
    free (data);
    if(has_asked_for_password){
        free (ctx.authValue);
    }
    return 0;
}

TSS2_TOOL_REGISTER("createseal", tss2_tool_onstart, tss2_tool_onrun, NULL)
