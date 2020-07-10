/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools/fapi/tss2_template.h"

/* Context struct used to store passed command line parameters */
static struct cxt {
    char const *path;
    char const *tpm2bPublic;
    char const *tpm2bPrivate;
    char const *policy;
    bool        overwrite;
} ctx;

/* Parse command line parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.path = value;
        break;
    case 'u':
        ctx.tpm2bPublic = value;
        break;
    case 'r':
        ctx.tpm2bPrivate = value;
        break;
    case 'l':
        ctx.policy = value;
        break;
    }
    return true;
}

/* Define possible command line parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"force"   , no_argument      , NULL, 'f'},
        {"path"    , required_argument, NULL, 'p'},
        {"tpm2bPublic"    , required_argument, NULL, 'u'},
        {"tpm2bPrivate"    , required_argument, NULL, 'r'},
        {"policy"    , required_argument, NULL, 'l'},
    };
    return (*opts = tpm2_options_new ("fp:u:r:l", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path missing, use --path\n");
        return -1;
    }

    /* Check exclusive access to stdout */
    int count_out = 0;
    if (ctx.tpm2bPublic && !strcmp (ctx.tpm2bPublic, "-")) count_out +=1;
    if (ctx.tpm2bPrivate && !strcmp (ctx.tpm2bPrivate, "-")) count_out +=1;
    if (ctx.policy && !strcmp (ctx.policy, "-")) count_out +=1;
    if (count_out > 1) {
        fprintf (stderr, "Only one of --tpm2bPublic, --tpm2bPrivate and "\
        "--policy can print to - (standard output)\n");
        return -1;
    }

    /* Execute FAPI command with passed arguments */
    uint8_t *tpm2bPublic;
    size_t  tpm2bPublicSize;
    uint8_t *tpm2bPrivate;
    size_t  tpm2bPrivateSize;
    char *policy;
    TSS2_RC r = Fapi_GetTpmBlobs (fctx, ctx.path, &tpm2bPublic,
        &tpm2bPublicSize, &tpm2bPrivate, &tpm2bPrivateSize, &policy);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetTpmBlobs", r);
        return 1;
    }

    /* Write returned data to file(s) */
    if (ctx.tpm2bPublic) {
        r = open_write_and_close (ctx.tpm2bPublic, ctx.overwrite, tpm2bPublic,
            tpm2bPublicSize);
        if (r) {
            Fapi_Free (tpm2bPublic);
            return 1;
        }
    }

    if (ctx.tpm2bPrivate) {
        r = open_write_and_close (ctx.tpm2bPrivate, ctx.overwrite, tpm2bPrivate,
            tpm2bPrivateSize);
        if (r) {
            Fapi_Free (tpm2bPublic);
            Fapi_Free (tpm2bPrivate);
            return 1;
        }
    }

    if (ctx.policy) {
        r = open_write_and_close (ctx.policy, ctx.overwrite, policy,
            strlen(policy));
        if (r) {
            Fapi_Free (tpm2bPublic);
            Fapi_Free (tpm2bPrivate);
            Fapi_Free (policy);
            return 1;
        }
    }

    Fapi_Free (tpm2bPublic);
    Fapi_Free (tpm2bPrivate);
    Fapi_Free (policy);

    return 0;
}

TSS2_TOOL_REGISTER("gettpmblobs", tss2_tool_onstart, tss2_tool_onrun, NULL)
