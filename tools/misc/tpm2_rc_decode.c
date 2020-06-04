/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>

#include <tss2/tss2_rc.h>

#include "log.h"
#include "tpm2_tool.h"

#define TPM2_RC_MAX 0xffffffff

typedef struct tpm2_rc_ctx tpm2_rc_ctx;
struct tpm2_rc_ctx {
    TSS2_RC rc;
};

static tpm2_rc_ctx ctx;

static bool str_to_tpm_rc(const char *rc_str, TSS2_RC *rc) {

    uintmax_t rc_read = 0;
    char *end_ptr = NULL;

    rc_read = strtoumax(rc_str, &end_ptr, 0);
    if (rc_read > TPM2_RC_MAX) {
        LOG_ERR("invalid TSS2_RC");
        return false;
    }

    /* apply the TPM2_RC_MAX mask to the possibly larger uintmax_t */
    *rc = rc_read & TPM2_RC_MAX;

    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Expected 1 rc code, got: %d", argc);
    }

    return str_to_tpm_rc(argv[0], &ctx.rc);
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg, TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    const char *e = Tss2_RC_Decode(ctx.rc);
    tpm2_tool_output("%s\n", e);

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("rc_decode", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
