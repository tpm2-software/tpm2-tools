/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char  const *policyPath;
    char  const *keyPath; /* the path to the signing key */
    char  const *policyRef;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'P':
        ctx.policyPath = value;
        break;
    case 'p':
        ctx.keyPath = value;
        break;
    case 'r':
        ctx.policyRef = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"policyPath", required_argument, NULL, 'P'},
        {"keyPath",    required_argument, NULL, 'p'},
        {"policyRef",    required_argument, NULL, 'r'},
    };
    return (*opts = tpm2_options_new ("P:p:r.", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.policyPath) {
        fprintf (stderr, "policy path to sign is missing, pass" \
            "--policyPath\n");
        return -1;
    }
    if (!ctx.keyPath) {
        fprintf (stderr, "key path for signing key is missing, pass" \
            "--keyPath\n");
        return -1;
    }

    /* Read ciphertext file */
    TSS2_RC r;
    uint8_t *policyRef = NULL;
    size_t policyRefSize = 0;
    if (ctx.policyRef){
        r = open_read_and_close (ctx.policyRef, (void**)&policyRef,
            &policyRefSize);
        if (r){
            return 1;
        }
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_AuthorizePolicy (fctx, ctx.policyPath, ctx.keyPath, policyRef,
        policyRefSize);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR ("Fapi_AuthorizePolicy", r);
        free (policyRef);
        return 1;
    }

    free (policyRef);

    return 0;
}

TSS2_TOOL_REGISTER("authorizepolicy", tss2_tool_onstart, tss2_tool_onrun, NULL)
