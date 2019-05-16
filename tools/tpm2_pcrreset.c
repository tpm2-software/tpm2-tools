/* SPDX-License-Identifier: BSD-3-Clause */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "pcr.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_pcr_reset_ctx tpm_pcr_reset_ctx;
struct tpm_pcr_reset_ctx {
    bool            pcr_list[TPM2_MAX_PCRS];
};

static tpm_pcr_reset_ctx ctx;

static bool pcr_reset_one(ESYS_CONTEXT *ectx,
                          TPMI_DH_PCR pcr_index) {

    TSS2_RC rval = Esys_PCR_Reset(ectx, pcr_index, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Could not reset PCR index: %d", pcr_index);
        LOG_PERR(Esys_PCR_Reset, rval);
        return false;
    }

    return true;
}

static bool pcr_reset(ESYS_CONTEXT *ectx) {
    size_t i;

    for (i = 0; i < TPM2_MAX_PCRS; i++) {
        if(!ctx.pcr_list[i])
            continue;

        bool result = pcr_reset_one(ectx, i);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool on_arg(int argc, char** argv){
    int i;
    uint32_t pcr;

    memset(ctx.pcr_list, 0, TPM2_MAX_PCRS);

    if (argc < 1) {
        LOG_ERR("Expected at least one PCR index"
                "ie: <pcr index>, got: 0");
        return false;
    }

    for(i = 0; i < argc; i++){
        if(!pcr_get_id(argv[i], &pcr))
            return false;

        ctx.pcr_list[pcr] = 1;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {
    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return pcr_reset(ectx) != true;
}

void tpm2_tool_onexit(void) {
    return;
}
