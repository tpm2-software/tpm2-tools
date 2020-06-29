/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char const *keyPath;
    char const *digest;
    char const *signature;
    char const *publicKey;
    char const *certificate;
    bool        overwrite;
    char const *padding;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'c':
        ctx.certificate = value;
        break;
    case 'd':
        ctx.digest = value;
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.keyPath = value;
        break;
    case 'k':
        ctx.publicKey = value;
        break;
    case 'o':
        ctx.signature = value;
        break;
    case 's':
        ctx.padding = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"keyPath",     required_argument, NULL, 'p'},
        {"padding",     required_argument, NULL, 's'},
        {"digest",      required_argument, NULL, 'd'},
        {"signature",   required_argument, NULL, 'o'},
        {"publicKey",   required_argument, NULL, 'k'},
        {"force",       no_argument      , NULL, 'f'},
        {"certificate", required_argument, NULL, 'c'},

    };
    return (*opts = tpm2_options_new ("c:d:fp:k:o:s:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {

    /* Check availability of required parameters */
    if (!ctx.digest) {
        fprintf (stderr, "digest missing, use --digest\n");
        return -1;
    }
    if (!ctx.keyPath) {
        fprintf (stderr, "key path missing, use --keyPath\n");
        return -1;
    }
    if (!ctx.signature) {
        fprintf (stderr, "signature missing, use --signature\n");
        return -1;
    }

    /* Check exclusive access to stdout */
    int count_out = 0;
    if (ctx.certificate && !strcmp (ctx.certificate, "-")) count_out +=1;
    if (ctx.signature && !strcmp (ctx.signature, "-")) count_out +=1;
    if (ctx.publicKey && !strcmp (ctx.publicKey, "-")) count_out +=1;
    if (count_out > 1) {
        fprintf (stderr, "Only one of --certificate, --signature and "\
        "--publicKey can print to - (standard output)\n");
        return -1;
    }

    /* Read data needed to create signature */
    uint8_t *digest, *signature;
    size_t digestSize, signatureSize;
    char *publicKey, *certificate = NULL;
    TSS2_RC r = open_read_and_close (ctx.digest, (void**)&digest, &digestSize);
    if (r){
        return 1;
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_Sign (fctx, ctx.keyPath, ctx.padding, digest,
        digestSize, &signature, &signatureSize, &publicKey, &certificate);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_Sign", r);
        free (digest);
        return 1;
    }
    free (digest);

    /* Write returned data to file(s) */
    if (ctx.certificate && certificate && strlen(certificate)) {
            r = open_write_and_close (ctx.certificate, ctx.overwrite,
                certificate, strlen(certificate));
            if (r) {
                Fapi_Free (certificate);
                Fapi_Free (signature);
                Fapi_Free (publicKey);
                return 1;
            }
    }
    Fapi_Free (certificate);

    if (ctx.signature && signature) {
        r = open_write_and_close (ctx.signature, ctx.overwrite, signature,
            signatureSize);
        if (r) {
            Fapi_Free (signature);
            Fapi_Free (publicKey);
            return 1;
        }
    }
    Fapi_Free (signature);

    if (ctx.publicKey && publicKey) {
        r = open_write_and_close (ctx.publicKey, ctx.overwrite, publicKey,
                strlen(publicKey));
        if (r) {
            Fapi_Free (publicKey);
            return 1;
        }
    }
    Fapi_Free (publicKey);

    return 0;
}

TSS2_TOOL_REGISTER("sign", tss2_tool_onstart, tss2_tool_onrun, NULL)
