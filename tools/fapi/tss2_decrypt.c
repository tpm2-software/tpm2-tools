/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *keyPath;
    char const *plainText;
    char const *cipherText;
    bool        overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'i':
        ctx.cipherText = value;
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'o':
        ctx.plainText = value;
        break;
    case 'p':
        ctx.keyPath = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"keyPath",     required_argument, NULL, 'p'},
        {"cipherText", required_argument, NULL, 'i'},
        {"force"      , no_argument      , NULL, 'f'},
        {"plainText"     , required_argument, NULL, 'o'},
    };
    return (*opts = tpm2_options_new ("i:f:o:p:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.keyPath) {
        fprintf (stderr, "No key path provided, use --keyPath\n");
        return -1;
    }
    if (!ctx.cipherText) {
        fprintf (stderr, "No encrypted text provided, use --cipherText\n");
        return -1;
    }
    if (!ctx.plainText) {
        fprintf (stderr, "No output file provided, use --plainText\n");
        return -1;
    }

    /* Read ciphertext file */
    uint8_t* cipherText;
    size_t cipherTextSize;
    TSS2_RC r = open_read_and_close (ctx.cipherText, (void**)&cipherText,
        &cipherTextSize);
    if (r){
        LOG_PERR ("open_read_and_close cipherText", r);
        return r;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *plainText;
    size_t plainTextSize;
    r = Fapi_Decrypt (fctx, ctx.keyPath, cipherText, cipherTextSize,
        &plainText, &plainTextSize);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_Decrypt", r);
        return 1;
    }
    free(cipherText);

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.plainText, ctx.overwrite, plainText,
        plainTextSize);
    if (r){
        LOG_PERR ("open_write_and_close plainText", r);
        return r;
    }

    Fapi_Free (plainText);
    return r;
}
