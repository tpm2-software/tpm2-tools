//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <tss2/tss2_esys.h>

#include "tpm2_options.h"
#include "log.h"
#include "files.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_random_ctx tpm_random_ctx;
struct tpm_random_ctx {
    bool output_file_specified;
    char *output_file;
    UINT16 num_of_bytes;
};

static tpm_random_ctx ctx;

static bool get_random_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_DIGEST *random_bytes;

    TSS2_RC rval = Esys_GetRandom(ectx,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  ctx.num_of_bytes, &random_bytes);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetRandom, rval);
        return false;
    }

    if (!ctx.output_file_specified) {
        UINT16 i;
        for (i = 0; i < random_bytes->size; i++) {
            tpm2_tool_output("%s0x%2.2X", i ? " " : "", random_bytes->buffer[i]);
        }
        tpm2_tool_output("\n");
        free(random_bytes);
        return true;
    }

    rval = files_save_bytes_to_file(ctx.output_file, random_bytes->buffer,
            random_bytes->size);
    if (!rval) {
        LOG_ERR("Failed to save bytes into file \"%s\"", ctx.output_file);
        free(random_bytes);
        return false;
    }

    free(random_bytes);
    return true;
}

static bool on_option(char key, char *value) {

    UNUSED(key);

    ctx.output_file_specified = true;
    ctx.output_file = value;

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one SIZE octets, got: %d", argc);
        return false;
    }

    bool result = tpm2_util_string_to_uint16(argv[0], &ctx.num_of_bytes);
    if (!result) {
        LOG_ERR("Error converting size to a number, got: \"%s\".",
                argv[0]);
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "out-file",   required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("o:", ARRAY_LEN(topts), topts, on_option, on_args,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    return get_random_and_save(ectx) != true;
}
