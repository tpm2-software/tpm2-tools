/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>


#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_capability.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_listpersistent_context tpm_listpersistent_context;
struct tpm_listpersistent_context {
    TPMI_ALG_HASH nameAlg;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
};

static tpm_listpersistent_context ctx = {
    .nameAlg = TPM2_ALG_NULL,
    .type = TPM2_ALG_NULL,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.nameAlg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got \"%s\"", value);
            return false;
        }
        break;
    case 'G':
        ctx.type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_symmetric
                |tpm2_alg_util_flags_asymmetric
                |tpm2_alg_util_flags_keyedhash);
        if (ctx.type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got \"%s\"", value);
            return false;
        }

        tpm2_alg_util_flags flags = tpm2_alg_util_algtoflags(ctx.type);
        if (flags & tpm2_alg_util_flags_keyedhash) {
            ctx.scheme = ctx.type;
            ctx.type = TPM2_ALG_KEYEDHASH;
        }

        if (flags & tpm2_alg_util_flags_symmetric) {
            ctx.scheme = ctx.type;
            ctx.type = TPM2_ALG_SYMCIPHER;
        }
    }

    return true;
}

static int read_public(ESYS_CONTEXT *ectx,
        TPM2_HANDLE objectHandle, TPM2B_PUBLIC **outPublic) {

    TSS2_RC rval;
    ESYS_TR objHandle = ESYS_TR_NONE;

    rval = Esys_TR_FromTPMPublic(ectx, objectHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &objHandle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return -1;
    }

    rval = Esys_ReadPublic(ectx, objHandle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        outPublic, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ReadPublic, rval);
        return -1;
    }

    return 0;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        {"halg", required_argument, NULL, 'g'},
        {"kalg", required_argument, NULL, 'G'},
    };

    *opts = tpm2_options_new("g:G:", ARRAY_LEN(topts), topts, on_option, NULL,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMS_CAPABILITY_DATA *capabilityData = NULL;
    int rc = 0;
    bool ret = tpm2_capability_get(ectx, TPM2_CAP_HANDLES,
                                TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES,
                                &capabilityData);
    if (!ret) {
        LOG_ERR("Failed to read TPM capabilities.");
        rc = 1;
        goto out;
    }

    UINT32 i;
    for (i = 0; i < capabilityData->data.handles.count; i++) {
        TPM2B_PUBLIC *outPublic = NULL;
        TPM2_HANDLE objectHandle = capabilityData->data.handles.handle[i];
        if (read_public(ectx, objectHandle, &outPublic)) {
            free(outPublic);
            rc = 2;
            goto out;
        }

        TPMI_ALG_KEYEDHASH_SCHEME kh_scheme = outPublic->publicArea.parameters.keyedHashDetail.scheme.scheme;
        TPMI_ALG_KEYEDHASH_SCHEME sym_scheme = outPublic->publicArea.parameters.symDetail.sym.algorithm;
        TPMI_ALG_PUBLIC type = outPublic->publicArea.type;
        TPMI_ALG_HASH nameAlg = outPublic->publicArea.nameAlg;
        if ((ctx.type != TPM2_ALG_NULL && ctx.type != type)
                || (ctx.nameAlg != TPM2_ALG_NULL && ctx.nameAlg != nameAlg)
                || (ctx.type == TPM2_ALG_KEYEDHASH && kh_scheme != ctx.scheme)
                || (ctx.type == TPM2_ALG_SYMCIPHER && sym_scheme != ctx.scheme)) {
            /* Skip, filter me out */
            goto cont;
        }

        tpm2_tool_output("- handle: 0x%x\n", objectHandle);
        tpm2_util_public_to_yaml(outPublic, "  ");
        tpm2_tool_output("\n");
    cont:
        free(outPublic);
    }

out:
    free(capabilityData);

    return rc;
}
