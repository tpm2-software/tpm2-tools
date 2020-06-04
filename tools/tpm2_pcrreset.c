/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

typedef struct tpm_pcr_reset_ctx tpm_pcr_reset_ctx;
struct tpm_pcr_reset_ctx {
    bool pcr_list[TPM2_MAX_PCRS];
};

static tpm_pcr_reset_ctx ctx;

static tool_rc pcr_reset_one(ESYS_CONTEXT *ectx, TPMI_DH_PCR pcr_index) {

    tool_rc rc = tpm2_pcr_reset(ectx, pcr_index);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not reset PCR index: %d", pcr_index);
    }

    return rc;
}

static tool_rc pcr_reset(ESYS_CONTEXT *ectx) {
    size_t i;

    for (i = 0; i < TPM2_MAX_PCRS; i++) {
        if (!ctx.pcr_list[i])
            continue;

        tool_rc rc = pcr_reset_one(ectx, i);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char** argv) {
    int i;
    uint32_t pcr;

    memset(ctx.pcr_list, 0, TPM2_MAX_PCRS);

    if (argc < 1) {
        LOG_ERR("Expected at least one PCR index"
                "ie: <pcr index>, got: 0");
        return false;
    }

    for (i = 0; i < argc; i++) {
        if (!pcr_get_id(argv[i], &pcr))
            return false;

        ctx.pcr_list[pcr] = 1;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return pcr_reset(ectx);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrreset", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
