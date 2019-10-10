/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char const *digest;
    char const *publicKeyPath;
    char const *signature;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'd':
        ctx.digest = value;
        break;
    case 'p':
        ctx.publicKeyPath = value;
        break;
    case 'i':
        ctx.signature = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"keyPath",     required_argument, NULL, 'p'},
        {"digest",      required_argument, NULL, 'd'},
        {"signature",   required_argument, NULL, 'i'}
    };
    return (*opts = tpm2_options_new ("d:p:i:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.publicKeyPath) {
        fprintf (stderr, "public key path parameter not provided, use " \
            "--keyPath\n");
        return -1;
    }
    if (!ctx.digest) {
        fprintf (stderr, "digest parameter not provided, use --digest\n");
        return -1;
    }
    if (!ctx.signature) {
        fprintf (stderr, "signature parameter not provided, use "\
            "--signature\n");
        return -1;
    }
    if (!strcmp ("-", ctx.signature)  && !strcmp("-", ctx.digest)) {
        fprintf (stderr, "At most one of --signature and --digest can be '-'"\
            " (standard input)\n");
        return -1;
    }

    /* Read data needed for signature verification */
    uint8_t *digest, *signature;
    size_t digestSize, signatureSize;
    TSS2_RC r = open_read_and_close (ctx.digest, (void**)&digest, &digestSize);
    if (r){
        LOG_PERR("open_read_and_close digest", r);
        return 1;
    }
    r = open_read_and_close (ctx.signature, (void**)&signature, &signatureSize);
    if (r) {
        LOG_PERR("open_read_and_close signature", r);
        free (digest);
        return 1;
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_VerifySignature (fctx, ctx.publicKeyPath,
        digest, digestSize, signature, signatureSize);
    if (r != TSS2_RC_SUCCESS){
        LOG_PERR("Fapi_Key_VerifySignature", r);
        return 1;
    }
    free (digest);
    free (signature);
    return 0;
}
