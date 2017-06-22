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
#include "tpm_table.h"

typedef struct tpm_random_ctx tpm_random_ctx;
struct tpm_random_ctx {
    bool output_file_specified;
    char output_file[PATH_MAX];
    UINT16 num_of_bytes;
    TSS2_SYS_CONTEXT *sapi_context;
    tpm_table *t;
};

static bool get_random_and_save(tpm_random_ctx *ctx) {

    TPM2B_DIGEST random_bytes = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TPM_RC rval = Tss2_Sys_GetRandom(ctx->sapi_context, NULL, ctx->num_of_bytes,
            &random_bytes, NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("TPM2_GetRandom Error. TPM Error:0x%x", rval);
        return false;
    }

    if (!ctx->output_file_specified) {

        char *s = string_bytes_to_hex(random_bytes.t.buffer, random_bytes.t.size);
        if (!s) {
        	LOG_ERR("oom");
        	return false;
        }

        TOOL_OUTPUT(ctx->t, "random", s);

        free(s);
        return true;
    }

    return files_save_bytes_to_file(ctx->output_file, (UINT8 *) random_bytes.t.buffer,
            random_bytes.t.size);
}

#define ARG_CNT (2 * (sizeof(long_options)/sizeof(long_options[0]) - 1))

static bool init(int argc, char *argv[], tpm_random_ctx *ctx) {

    static const char *short_options = "o:";
    static const struct option long_options[] = {
        { "output",   required_argument, NULL, 'o' },
        { NULL,   no_argument,       NULL,  '\0' },
    };

    if (argc !=2 && argc != 4) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    optind = 0; /* force reset of getopt() since we used gnu extensions in main, sic */
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'o':
            ctx->output_file_specified = true;
            snprintf(ctx->output_file, sizeof(ctx->output_file), "%s", optarg);
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

    bool result = string_bytes_get_uint16(argv[optind], &ctx->num_of_bytes);
    if (!result) {
        LOG_ERR("Error converting size to a number, got: \"%s\".",
                argv[optind]);
        return false;
    }

    return true;
}

ENTRY_POINT(getrandom) {

    (void)opts;
    (void)envp;

    tpm_random_ctx ctx = {
            .output_file_specified = false,
            .num_of_bytes = 0,
            .output_file = { 0 },
            .sapi_context = sapi_context,
			.t = table
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return get_random_and_save(&ctx) != true;
}
