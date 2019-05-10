/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_error.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

#define TPM2_RC_MAX 0xffffffff

typedef struct tpm2_rc_ctx tpm2_rc_ctx;
struct tpm2_rc_ctx {
    TSS2_RC rc;
};

tpm2_rc_ctx ctx;

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

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_arg,
            TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    const char *e = tpm2_error_str(ctx.rc);
    tpm2_tool_output("%s\n", e);

    return 0;
}
