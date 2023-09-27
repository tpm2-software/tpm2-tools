/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "tools/fapi/tss2_template.h"
#include "lib/tpm2.h"
#include "lib/files.h"

/* Context struct used to store passed commandline parameters */
static struct cxt {
    char const *data;
    char const *path;
    char const *tcti;
    bool        overwrite;
} ctx;

/* Parse commandline parameters */
static bool on_option(char key, char *value) {
    switch (key) {
    case 'c':
        ctx.data = value;
        break;
    case 'f':
        ctx.overwrite = true;
        break;
    case 'p':
        ctx.path = value;
        break;
    }
    return true;
}

/* Define possible commandline parameters */
static bool tss2_tool_onstart(tpm2_options **opts) {
    struct option topts[] = {
        {"path", required_argument, NULL, 'p'},
        {"context",required_argument, NULL, 'c'},
        {"force" , no_argument, NULL, 'f'},
        {"tcti", required_argument, NULL, 'T'},

    };
    return (*opts = tpm2_options_new ("c:fp:", ARRAY_LEN(topts), topts,
                                      on_option, NULL, 0)) != NULL;
}

/* Execute specific tool */
static int tss2_tool_onrun (FAPI_CONTEXT *fctx) {
    uint8_t blob_type;
    uint8_t *esys_blob = NULL;
    size_t esys_blob_size;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR esys_handle = ESYS_TR_NONE;
    ESYS_TR esys_handle_deser = ESYS_TR_NONE;
    FILE *stream = NULL;
    TPM2_HANDLE tpm_handle;
    TSS2_RC e_rc;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    tool_rc t_rc;

    /* Check availability of required parameters */
    if (!ctx.path) {
        fprintf (stderr, "path is missing, use --path\n");
        return -1;
    }

    if (!ctx.data) {
        ctx.data = "-";
    }

    /* Execute FAPI command with passed arguments */
    TSS2_RC r = Fapi_GetEsysBlob (fctx, ctx.path, &blob_type, &esys_blob, &esys_blob_size);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetAppData", r);
        return 1;
    }

    if (strcmp(ctx.data, "-")) {
        if (!ctx.overwrite) {
            FILE *fp = fopen(ctx.data, "rb");
            if (fp) {
                fclose(fp);
                LOG_ERR("Path: %s already exists. Please rename or delete the file!\n",
                ctx.data);
                goto error;
            }
        }
        stream = fopen(ctx.data, "w+b");
        if (!stream) {
            LOG_ERR("Could not open path \"%s\", due to error: \"%s\"", ctx.data,
                    strerror(errno));
            goto error;
        }
    } else {
        stream = stdout;
    }

    r = Fapi_GetTcti(fctx, &tcti);
    if (r != TSS2_RC_SUCCESS) {
        LOG_PERR ("Fapi_GetTcti", r);
        goto error;
    }

    e_rc = Esys_Initialize(&esys_ctx, tcti, NULL);

    if (blob_type == FAPI_ESYSBLOB_CONTEXTLOAD) {
        size_t offset = 0;
        TPMS_CONTEXT context;

        if (e_rc != TPM2_RC_SUCCESS) {
            LOG_PERR("Esys_Initialize", e_rc);
            goto error;
        }
         e_rc = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob, esys_blob_size, &offset, &context);
         if (e_rc != TPM2_RC_SUCCESS) {
             LOG_PERR("Tss2_MU_TPMS_CONTEXT_Unmarshal", e_rc);
             goto error;
         }
         e_rc = Esys_ContextLoad(esys_ctx, &context, &esys_handle);
         if (e_rc != TPM2_RC_SUCCESS) {
             LOG_PERR("Esys_ContextLoad", e_rc);
             goto error;
         }
         t_rc = files_save_tpm_context_to_file(esys_ctx, esys_handle, stream, false);
         if (t_rc != tool_rc_success) {
             goto error;
         }
         Esys_FlushContext(esys_ctx, esys_handle);
         Esys_Finalize(&esys_ctx);
    } else {
        t_rc = tpm2_tr_deserialize(esys_ctx, esys_blob, esys_blob_size, &esys_handle_deser);
        if (t_rc != tool_rc_success) {
             goto error;
        }
        e_rc = Esys_TR_GetTpmHandle(esys_ctx, esys_handle_deser, &tpm_handle);
        if (e_rc != TSS2_RC_SUCCESS) {
            LOG_PERR("Esys_TR_GetTpmHandle", e_rc);
            goto error;
        }
        int bytes_written = fprintf(stream,"0x%08x", tpm_handle);
        if (bytes_written != 10) {
            LOG_ERR("IO error for path \"%s\"", ctx.data);
            goto error;
        }

        Esys_TR_Close(esys_ctx, &esys_handle_deser);
        Esys_Finalize(&esys_ctx);
    }

    /* Free allocated variables */
    Fapi_Free (esys_blob);
    if (stream && stream != stdout) {
        fclose(stream);
    }

    return 0;

 error:
    if (stream && stream != stdout) {
        fclose(stream);
    }
    Fapi_Free (esys_blob);
    if (esys_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, esys_handle);
    }
    if (esys_handle_deser != ESYS_TR_NONE) {
        Esys_TR_Close(esys_ctx, &esys_handle_deser);
    }
    if (esys_ctx) {
        Esys_Finalize(&esys_ctx);
    }
    if (tcti) {
        Tss2_TctiLdr_Finalize(&tcti);
    }
    return 1;
}

TSS2_TOOL_REGISTER("gettpm2object", tss2_tool_onstart, tss2_tool_onrun, NULL)
