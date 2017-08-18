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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"

typedef struct tpm_readpub_ctx tpm_readpub_ctx;
struct tpm_readpub_ctx {
    TPMI_DH_OBJECT objectHandle;
    char *outFilePath;
    TSS2_SYS_CONTEXT *sapi_context;
};

static int read_public_and_save(tpm_readpub_ctx *ctx) {

    TPMS_AUTH_RESPONSE session_out_data;
    TSS2_SYS_RSP_AUTHS sessions_out_data;
    TPMS_AUTH_RESPONSE *session_out_data_array[1];

    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    session_out_data_array[0] = &session_out_data;
    sessions_out_data.rspAuths = &session_out_data_array[0];
    sessions_out_data.rspAuthsCount = ARRAY_LEN(session_out_data_array);

    TPM_RC rval = Tss2_Sys_ReadPublic(ctx->sapi_context, ctx->objectHandle, 0,
            &public, &name, &qualified_name, &sessions_out_data);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_ReadPublic error: rval = 0x%0x", rval);
        return false;
    }

    printf("\nTPM2_ReadPublic OutPut: \n");
    printf("name: \n");
    UINT16 i;
    for (i = 0; i < name.t.size; i++)
        printf("%02x ", name.t.name[i]);
    printf("\n");

    printf("qualified_name: \n");
    for (i = 0; i < qualified_name.t.size; i++)
        printf("%02x ", qualified_name.t.name[i]);
    printf("\n");

    /* TODO fix serialization */
    return files_save_bytes_to_file(ctx->outFilePath, (UINT8 *) &public,
            sizeof(public));
}

static bool init(int argc, char *argv[], tpm_readpub_ctx * ctx) {

    const char *short_options = "H:o:c:";
    static struct option long_options[] = {
        {"object",        required_argument, NULL,'H'},
        {"opu",           required_argument, NULL,'o'},
        {"contextObject", required_argument, NULL,'c'},
        {NULL,            no_argument,       NULL, '\0'}
    };

    union {
        struct {
            UINT8 H      : 1;
            UINT8 o      : 1;
            UINT8 c      : 1;
            UINT8 unused : 5;
        };
        UINT8 all;
    } flags = { .all = 0 };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return 0;
    }

    int opt = -1;
    bool result;
    char *context_file = NULL;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'H':
            result = tpm2_util_string_to_uint32(optarg, &ctx->objectHandle);
            if (!result) {
                return false;
            }
            flags.H = 1;
            break;
        case 'o':
            result = files_does_file_exist(optarg);
            if (result) {
                return false;
            }
            ctx->outFilePath = optarg;
            flags.o = 1;
            break;
        case 'c':
            context_file = optarg;
            flags.c = 1;
            break;
        }
    };

    if (!((flags.H || flags.c) && flags.o)) {
        showArgMismatch(argv[0]);
        return false;
    }

    if (flags.c) {
        result = files_load_tpm_context_from_file(ctx->sapi_context, &ctx->objectHandle,
                context_file);
        if (!result) {
            return false;
        }
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    (void)opts;
    (void)envp;

    tpm_readpub_ctx ctx = {
            .objectHandle = 0,
            .outFilePath = NULL,
            .sapi_context = sapi_context
    };

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    return read_public_and_save(&ctx) != true;
}
