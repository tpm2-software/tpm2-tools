//**********************************************************************;
// Copyright (c) 2019, Sebastien LE STUM
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
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
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

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

/* Spec enforce input data to be not longer than 128 bytes */
#define MAX_SIZE_TO_READ 128

typedef struct tpm_stirrandom_ctx tpm_stirrandom_ctx;
struct tpm_stirrandom_ctx {
    TPM2B_SENSITIVE_DATA in_data;
    char *in_file;
};

static tpm_stirrandom_ctx ctx;

static bool do_stirrandom(ESYS_CONTEXT *ectx) {

    TSS2_RC rval = Esys_StirRandom(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                                   ESYS_TR_NONE, &ctx.in_data);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Error while injecting specified additionnal data into TPM "
                "random pool");
        LOG_PERR(Esys_StirRandom, rval);
        return false;
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Only supports one FILE_INPUT file, got %d arguments", argc);
        return false;
    }

    ctx.in_file = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_args, 0);

    return *opts != NULL;
}

static bool load_sensitive(void) {

    ctx.in_data.size = MAX_SIZE_TO_READ;

    bool res = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
                        ctx.in_file, &ctx.in_data.size, ctx.in_data.buffer);
    if (!res) {
        LOG_ERR("Error while reading data from file or stdin");
        return false;
    }

    if (ctx.in_data.size == 0) {
        LOG_ERR("Data size to send is zero");
        return false;
    }

    LOG_INFO("Submitting %d bytes to TPM", ctx.in_data.size);

    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!load_sensitive()) {
        return 1;
    }

    return do_stirrandom(ectx) != true;
}
