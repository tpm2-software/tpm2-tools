/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    uint32_t   *pcrList;
    size_t     pcrListSize;
    char const *keyPath;
    char const *qualifyingData;
    char const *quoteInfo;
    char const *pcrLog;
    char const *signature;
    char const *certificate;
    bool        overwrite;
} ctx;

/**
 * Split the comma separated input, parse each token as number,
 * put the numbers in the array output.  Allocate memory for
 * output to hold the numbers.
 *
 * On failure returns false and output is not allocated.
 * On success the caller frees output.
 */
static inline bool extract_pcrs(char *input, uint32_t **output, size_t *list_size) {
    size_t size = 1;
    char *temp = input;
    while ((temp = strchr (temp+1, ','))) size++;
    *output = malloc (sizeof(uint32_t) * (size));
    if (!*output) {
        fprintf (stderr, "malloc failed: %m\n");
        return false;
    }
    char *x = strtok_r (input, ",", &temp);
    if (!tpm2_util_string_to_uint32(x, output[0])) {
        fprintf (stderr, "%s cannot be used as PCR\n", x);
        free (*output);
        return false;
    }
    size = 0;
    while ((x = strtok_r (NULL, ",", &temp))) {
      if (!tpm2_util_string_to_uint32(x, &(*output)[++size])) {
            fprintf (stderr, "%s cannot be used as PCR\n", x);
            free (*output);
            return false;
        }
    }

    *list_size = size+1;

    return true;
}

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    (void)value;
    switch (key) {
    case 'x':
        return extract_pcrs(value, &ctx.pcrList, &ctx.pcrListSize);
    case 'Q':
        ctx.qualifyingData = value;
        break;
    case 'l':
        ctx.pcrLog = value;
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.keyPath = value;
        break;
    case 'q':
        ctx.quoteInfo = value;
        break;
    case 'o':
        ctx.signature = value;
        break;
    case 'c':
        ctx.certificate = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"pcrList"       , required_argument, NULL, 'x'},
        {"keyPath"        , required_argument, NULL, 'p'},
        {"qualifyingData", required_argument, NULL, 'Q'},
        {"quoteInfo"     , required_argument, NULL, 'q'},
        {"signature"      , required_argument, NULL, 'o'},
        {"pcrLog"        , required_argument, NULL, 'l'},
        {"certificate"    , required_argument, NULL, 'c'},
        {"force"          , no_argument      , NULL, 'f'}
    };
    return (*opts = tpm2_options_new ("x:Q:l:fp:q:o:c:", ARRAY_LEN(topts),
        topts, on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.pcrList) {
        fprintf (stderr, "No PCRs were chosen, use --pcrList\n");
        return -1;
    }
    if (!ctx.keyPath) {
        fprintf (stderr, "No key path provided, use --keyPath\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!ctx.quoteInfo) {
        fprintf (stderr, "No quoteInfo provided, use --quoteInfo\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!ctx.signature) {
        fprintf (stderr, "No signature provided, use --signature\n");
        free (ctx.pcrList);
        return -1;
    }

    /* Check exclusive access to stdout */
    int count_out = 0;
    if (ctx.quoteInfo && !strcmp (ctx.quoteInfo, "-")) count_out +=1;
    if (ctx.pcrLog && !strcmp (ctx.pcrLog, "-")) count_out +=1;
    if (ctx.signature && !strcmp (ctx.signature, "-")) count_out +=1;
    if (ctx.certificate && !strcmp (ctx.certificate, "-")) count_out +=1;
    if (count_out > 1) {
        fprintf (stderr, "Only one of --quoteInfo, --pcrLog, --signature and "\
            "--certificate can print to - (standard output)\n");
        free (ctx.pcrList);
        return -1;
    }

    /* Read qualifyingData file */
    TSS2_RC r;
    uint8_t *qualifyingData = NULL;
    size_t qualifyingDataSize = 0;
    if (ctx.qualifyingData) {
        r = open_read_and_close (ctx.qualifyingData,
            (void*)&qualifyingData, &qualifyingDataSize);
        if (r) {
          free (ctx.pcrList);
          return 1;
        }
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *signature;
    size_t signatureSize;
    char *quoteInfo, *pcrLog = NULL, *certificate = NULL;
    r = Fapi_Quote (fctx, ctx.pcrList, ctx.pcrListSize, ctx.keyPath,
        NULL, qualifyingData, qualifyingDataSize, &quoteInfo,
        &signature, &signatureSize, ctx.pcrLog ? &pcrLog : NULL, &certificate);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_Quote", r);
        free (ctx.pcrList);
        free (qualifyingData);
        return 1;
    }

    free (ctx.pcrList);
    free (qualifyingData);

    /* Write returned data to file(s) */
    if (ctx.quoteInfo && quoteInfo) {
        r = open_write_and_close (ctx.quoteInfo, ctx.overwrite, quoteInfo,
            strlen(quoteInfo));
        if (r) {
            Fapi_Free (quoteInfo);
            if (ctx.pcrLog)
                Fapi_Free (pcrLog);
            Fapi_Free (signature);
            Fapi_Free (certificate);
            return 1;
        }
    }

    Fapi_Free (quoteInfo);

    if (ctx.pcrLog && pcrLog) {
        r = open_write_and_close (ctx.pcrLog, ctx.overwrite, pcrLog,
            strlen(pcrLog));
        if (r) {
            Fapi_Free (pcrLog);
            Fapi_Free (signature);
            Fapi_Free (certificate);
            return 1;
        }
    }
    if (ctx.pcrLog)
        Fapi_Free (pcrLog);

    if (ctx.signature && signature) {
        r = open_write_and_close (ctx.signature, ctx.overwrite, signature,
            signatureSize);
        if (r) {
            Fapi_Free (signature);
            Fapi_Free (certificate);
            return 1;
        }
    }
    Fapi_Free (signature);

    if (ctx.certificate && certificate) {
        r = open_write_and_close (ctx.certificate, ctx.overwrite, certificate,
            strlen(certificate));
        if (r) {
            Fapi_Free (certificate);
            return 1;
        }
    }
    Fapi_Free (certificate);

    return 0;
}

TSS2_TOOL_REGISTER("quote", tss2_tool_onstart, tss2_tool_onrun, NULL)
