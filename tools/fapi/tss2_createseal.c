/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* needed to conditionally free variable authValue */
bool has_asked_for_password = false;

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *keyPath;
    char const *keyType;
    char const *policyPath;
    char       *authValue;
    char const *data;
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
    }
    return true;
}

/* Define possible command line parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path",       required_argument, NULL, 'p'},
        {"type",       required_argument, NULL, 't'},
        {"policyPath", required_argument, NULL, 'P'},
        {"authValue",  required_argument, NULL, 'a'},
        {"data",       required_argument, NULL, 'i'}
    };
    return (*opts = tpm2_options_new ("a:p:P:t:i:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.keyPath) {
        fprintf (stderr, "key path missing, use --path\n");
        return -1;
    }
    if (!ctx.data) {
        fprintf (stderr, "data to seal missing, use --data\n");
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
    uint8_t* data;
    size_t dataSize;
    TSS2_RC r = open_read_and_close (ctx.data, (void**)&data, &dataSize);
    if (r){
        LOG_PERR ("open_read_and_close data", r);
        return r;
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_CreateSeal (fctx, ctx.keyPath, ctx.keyType,
        dataSize, ctx.policyPath, ctx.authValue, data);
    if (r != TSS2_RC_SUCCESS){
        if(has_asked_for_password){
            free (ctx.authValue);
        }
        LOG_PERR ("Fapi_CreateSeal", r);
        return 1;
    }
    Fapi_Free(data);
    if(has_asked_for_password){
        free (ctx.authValue);
    }
    return 0;
}
