//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
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
