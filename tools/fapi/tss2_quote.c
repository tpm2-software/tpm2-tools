/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

/* Context struct used to store passed command line parameters */
static struct cxt {
    uint32_t   *pcrList;
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
 * output to hold the numbers.  The last element of output is -1.
 *
 * On failure returns false and output is not allocated.
 * On success the caller frees output.
 */
static inline bool extract_pcrs(char *input, uint32_t **output) {
    size_t size = 1;
    char *temp = input;
    while ((temp = strchr (temp+1, ','))) size++;
    *output = malloc (sizeof(uint32_t) * (size + 1));
    if (!*output) {
        fprintf (stderr, "malloc failed: %m\n");
        return false;
    }
    (*output)[size] = -1;
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
    return true;
}

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    (void)value;
    switch (key) {
    case 'x':
        return extract_pcrs(value, &ctx.pcrList);
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
bool tss2_tool_onstart(tpm2_options **opts) {
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
    return (*opts = tpm2_options_new ("x:Q:l:f:p:q:o:c:", ARRAY_LEN(topts),
        topts, on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
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
    if (!ctx.qualifyingData) {
        fprintf (stderr, "No qualifying data provided, use "\
            "--qualifyingData\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!ctx.signature) {
        fprintf (stderr, "No signature provided, use --signature\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!ctx.pcrLog) {
        fprintf (stderr, "No PCR event log provided, use --pcrLog\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!ctx.certificate) {
        fprintf (stderr, "No Certificate provided, use --certificate\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!ctx.quoteInfo) {
        fprintf (stderr, "No quoteInfo provided, use --quoteInfo\n");
        free (ctx.pcrList);
        return -1;
    }
    if (!strcmp (ctx.quoteInfo, "-") + !strcmp (ctx.pcrLog, "-") +
        !strcmp (ctx.signature, "-") + !strcmp (ctx.certificate, "-") > 1) {
            fprintf (stderr, "Only one of --quoteInfo, --pcrLog, "\
                "--signature and --certificate can print to standard "\
                "output");
            free (ctx.pcrList);
        return -1;
    }

    /* Read qualifyingData file */
    uint8_t *qualifyingData;
    size_t qualifyingDataSize;
    TSS2_RC r = open_read_and_close (ctx.qualifyingData, (void*)&qualifyingData,
        &qualifyingDataSize);
    if (r) {
      free (ctx.pcrList);
      return 1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *signature;
    size_t signatureSize;
    char *quoteInfo, *pcrLog = NULL, *certificate = NULL;
    r = Fapi_Quote (fctx, ctx.pcrList, 1, ctx.keyPath,
        NULL, qualifyingData, qualifyingDataSize, &quoteInfo,
        &signature, &signatureSize, &pcrLog, &certificate);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_Quote", r);
        free (ctx.pcrList);
        free (qualifyingData);
        return 1;
    }

    free (ctx.pcrList);
    free (qualifyingData);

    /* Write returned data to file(s) */
    r = open_write_and_close (ctx.quoteInfo, ctx.overwrite, quoteInfo, 0);
    if (r){
        LOG_PERR ("open_write_and_close quoteInfo", r);
        Fapi_Free (quoteInfo);
        if (pcrLog){
            Fapi_Free (pcrLog);
        }
        Fapi_Free (signature);
        return 1;
    }

    Fapi_Free (quoteInfo);

    if (pcrLog){
        r = open_write_and_close (ctx.pcrLog, ctx.overwrite, pcrLog,
            0);
        if (r){
            LOG_PERR ("open_write_and_close pcrLog", r);
            Fapi_Free (pcrLog);
            Fapi_Free (signature);
            return 1;
        }
        Fapi_Free (pcrLog);
    }

    r = open_write_and_close (ctx.signature, ctx.overwrite, signature,
        signatureSize);
    if (r) {
        LOG_PERR ("open_write_and_close signature", r);
        Fapi_Free (signature);
        return 1;
    }
    Fapi_Free (signature);

    r = open_write_and_close (ctx.certificate, ctx.overwrite, certificate,
        strlen(certificate));
    if (r) {
        LOG_PERR ("open_write_and_close certificate", r);
        Fapi_Free (certificate);
        return 1;
    }
    Fapi_Free (certificate);

    return 0;
}
