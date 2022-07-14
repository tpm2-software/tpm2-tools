/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

typedef struct tpm_pcr_reset_ctx tpm_pcr_reset_ctx;
struct tpm_pcr_reset_ctx {
    /*
     * Inputs
     */
    bool pcr_list[TPM2_MAX_PCRS];

    /*
     * Outputs
     */
};

static tpm_pcr_reset_ctx ctx;

static tool_rc pcr_reset(ESYS_CONTEXT *ectx) {

    size_t i;
    for (i = 0; i < TPM2_MAX_PCRS; i++) {
        if (!ctx.pcr_list[i]) {
            continue;
        }

        tool_rc rc = tpm2_pcr_reset(ectx, i);
        if (rc != tool_rc_success) {
            LOG_ERR("Could not reset PCR index: %ld", i);
            return rc;
        }
    }

    return tool_rc_success;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */

    return tool_rc_success;
}

static tool_rc check_options(void) {

    return tool_rc_success;
}

static bool on_arg(int argc, char** argv) {

    if (argc < 1) {
        LOG_ERR("Expected at least one PCR index"
                "ie: <pcr index>, got: 0");
        return false;
    }

    int i = 0;
    uint32_t pcr = 0;
    bool is_valid_pcr_index = false;
    memset(ctx.pcr_list, 0, TPM2_MAX_PCRS);
    for (i = 0; i < argc; i++) {
        is_valid_pcr_index = pcr_get_id(argv[i], &pcr);
        if (!is_valid_pcr_index) {
            return false;
        }
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

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = pcr_reset(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrreset", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
