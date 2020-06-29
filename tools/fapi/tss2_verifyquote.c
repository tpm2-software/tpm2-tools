/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char *publicKeyPath;
    char const *qualifyingData;
    char const *quoteInfo;
    char const *signature;
    char const *pcrLog;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'Q':
        ctx.qualifyingData = value;
        break;
    case 'l':
        ctx.pcrLog = value;
        break;
    case 'q':
        ctx.quoteInfo = value;
        break;
    case 'k':
        ctx.publicKeyPath = value;
        break;
    case 'i':
        ctx.signature = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"publicKeyPath",   required_argument, NULL, 'k'},
        {"qualifyingData",  required_argument, NULL, 'Q'},
        {"quoteInfo",       required_argument, NULL, 'q'},
        {"signature",       required_argument, NULL, 'i'},
        {"pcrLog",          required_argument, NULL, 'l'}
    };
    return (*opts = tpm2_options_new ("k:Q:q:i:l:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.quoteInfo) {
        fprintf (stderr, "quote info parameter not provided, use "\
            "--quoteInfo\n");
        return -1;
    }
    if (!ctx.publicKeyPath) {
        fprintf (stderr, "publicKeyPath parameter not provided, use "\
            "--publicKeyPath\n");
        return -1;
    }
    if (!ctx.signature) {
        fprintf (stderr, "signature parameter not provided, use"\
            " --signature\n");
        return -1;
    }

    /* Check exclusive access to stdin */
    int count_in = 0;
    if (ctx.qualifyingData && !strcmp (ctx.qualifyingData, "-")) count_in +=1;
    if (ctx.signature && !strcmp (ctx.signature, "-")) count_in +=1;
    if (ctx.quoteInfo && !strcmp (ctx.quoteInfo, "-")) count_in +=1;
    if (ctx.pcrLog && !strcmp (ctx.pcrLog, "-")) count_in +=1;
    if (count_in > 1) {
        fprintf (stderr, "Only one of --qualifyingData, --signature, "\
        " --quoteInfo and --pcrLog can read from - (standard input)\n");
        return -1;
    }

    /* Read qualifyingData, signature, quoteInfo and pcrLog from file */
    TSS2_RC r;
    uint8_t *qualifyingData = NULL;
    size_t qualifyingDataSize = 0;
    if (ctx.qualifyingData) {
        r = open_read_and_close (ctx.qualifyingData,
            (void**)&qualifyingData, &qualifyingDataSize);
        if (r) {
            return -1;
        }
    }

    uint8_t *signature = NULL;
    size_t signatureSize = 0;
    if (ctx.signature) {
        r = open_read_and_close (ctx.signature, (void**)&signature, &signatureSize);
        if (r) {
            free (qualifyingData);
            return -1;
        }
    }

    char *quoteInfo = NULL;
    if (ctx.quoteInfo) {
        r = open_read_and_close (ctx.quoteInfo, (void**)&quoteInfo, NULL);
        if (r) {
            free (qualifyingData);
            free (signature);
            return -1;
        }
    }

    char *pcrLog = NULL;
    if (ctx.pcrLog) {
        r = open_read_and_close (ctx.pcrLog, (void**)&pcrLog, NULL);
        if (r) {
            free (qualifyingData);
            free (signature);
            free (quoteInfo);
            return -1;
        }
    }

    /* Execute FAPI command with passed arguments */
    r = Fapi_VerifyQuote (fctx, ctx.publicKeyPath, qualifyingData,
        qualifyingDataSize, quoteInfo, signature, signatureSize,
        pcrLog);
    if (r != TSS2_RC_SUCCESS){
        free (qualifyingData);
        free (signature);
        free (quoteInfo);
        free (pcrLog);
        LOG_PERR ("Fapi_VerifyQuote", r);
        return 1;
    }

    free (qualifyingData);
    free (signature);
    free (quoteInfo);
    free (pcrLog);

    return 0;
}

TSS2_TOOL_REGISTER("verifyquote", tss2_tool_onstart, tss2_tool_onrun, NULL)
