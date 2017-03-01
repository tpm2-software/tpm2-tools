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

#include <getopt.h>
#include <limits.h>
#include <sapi/tpm20.h>

#include "log.h"
#include "files.h"
#include "main.h"
#include "options.h"
#include "password_util.h"
#include "string-bytes.h"

typedef struct tpm_random_ctx tpm_random_ctx;
struct tpm_random_ctx {
    char output_file[PATH_MAX];
    UINT16 num_of_bytes;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool get_random_and_save(tpm_random_ctx *ctx) {

    TPM2B_DIGEST random_bytes = { { sizeof(TPM2B_DIGEST) - 2 } };

    TPM_RC rval = Tss2_Sys_GetRandom(ctx->sapi_context, NULL, ctx->num_of_bytes,
            &random_bytes, NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("TPM2_GetRandom Error. TPM Error:0x%x", rval);
        return false;
    }

    printf("byte size: %d\n", random_bytes.t.size);
    UINT16 i;
    for (i = 0; i < random_bytes.t.size; i++)
        printf(" 0x%2.2X", random_bytes.t.buffer[i]);
    printf("\n");

    return files_save_bytes_to_file(ctx->output_file, (UINT8 *) random_bytes.t.buffer,
            random_bytes.t.size);
}

#define ARG_CNT (2 * (sizeof(long_options)/sizeof(long_options[0]) - 1))

static bool init(int argc, char *argv[], tpm_random_ctx *ctx) {

    static const char *short_options = "s:o:p:d:hv";
    static const struct option long_options[] = {
        { "size", required_argument, NULL, 's' },
        { "of",   required_argument, NULL, 'o' },
        { NULL,   no_argument,       NULL,  '\0' },
    };

    struct {
        UINT8 s      : 1;
        UINT8 o      : 1;
        UINT8 unused : 6;
    } flags = { 0 };

    /*
     * subtract 1 from argc to disregard argv[0]
     * ALL options are required.
     * */
    if ((argc - 1) != ARG_CNT) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    bool result;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL))
            != -1) {
        switch (opt) {
        case 's':
            result = string_bytes_get_uint16(optarg, &ctx->num_of_bytes);
            if (!result) {
                LOG_ERR("Error converting size to a number, got: \"%s\".",
                        optarg);
                return false;
            }
            flags.s = 1;
            break;
        case 'o':
            snprintf(ctx->output_file, sizeof(ctx->output_file), "%s", optarg);
            flags.o = 1;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            return false;
        }
    }

    if (!(flags.s && flags.o)) {
        LOG_ERR("Must specify size and output file");
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
            TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    tpm_random_ctx ctx = {
            .num_of_bytes = 0,
            .output_file = { 0 },
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return get_random_and_save(&ctx) != true;
}
