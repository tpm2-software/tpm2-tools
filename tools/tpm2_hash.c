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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

typedef struct tpm_hash_ctx tpm_hash_ctx;
struct tpm_hash_ctx {
    TPMI_RH_HIERARCHY hierarchyValue;
    TPM2B_MAX_BUFFER data;
    TPMI_ALG_HASH  halg;
    char *outHashFilePath;
    char *outTicketFilePath;
    TSS2_SYS_CONTEXT *sapi_context;
};

static bool get_hierarchy_value(const char *hiearchy_code,
        TPMI_RH_HIERARCHY *hierarchy_value) {

    size_t len = strlen(hiearchy_code);
    if (len != 1) {
        LOG_ERR("Hierarchy Values are single characters, got: %s",
                hiearchy_code);
        return false;
    }

    switch (hiearchy_code[0]) {
    case 'e':
        *hierarchy_value = TPM_RH_ENDORSEMENT;
        break;
    case 'o':
        *hierarchy_value = TPM_RH_OWNER;
        break;
    case 'p':
        *hierarchy_value = TPM_RH_PLATFORM;
        break;
    case 'n':
        *hierarchy_value = TPM_RH_NULL;
        break;
    default:
        LOG_ERR("Unknown hierarchy value: %s", hiearchy_code);
        return false;
    }
    return true;
}

static bool hash_and_save(tpm_hash_ctx *ctx) {

    TPM2B_DIGEST outHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_HASHCHECK validation;

    UINT32 rval = Tss2_Sys_Hash(ctx->sapi_context, 0, &ctx->data, ctx->halg,
            ctx->hierarchyValue, &outHash, &validation, 0);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("TPM2_Sys_Hash Error. TPM Error:0x%x", rval);
        return false;
    }

    printf("\nhash value(hex type): ");
    UINT16 i;
    for (i = 0; i < outHash.t.size; i++)
        printf("%02x ", outHash.t.buffer[i]);
    printf("\n");

    printf("\nvalidation value(hex type): ");
    for (i = 0; i < validation.digest.t.size; i++)
        printf("%02x ", validation.digest.t.buffer[i]);
    printf("\n");

    /* TODO fix serialization */
    bool result = files_save_bytes_to_file(ctx->outHashFilePath, (UINT8 *) &outHash,
            sizeof(outHash));
    if (!result) {
        return false;
    }

    /* TODO fix serialization */
    return files_save_bytes_to_file(ctx->outTicketFilePath, (UINT8 *) &validation,
            sizeof(validation));
}

static bool init(int argc, char *argv[], tpm_hash_ctx *ctx) {

    static struct option long_options[] = {
        {"Hierachy", required_argument, NULL, 'H'},
        {"halg",     required_argument, NULL, 'g'},
        {"infile",   required_argument, NULL, 'I'},
        {"outfile",  required_argument, NULL, 'o'},
        {"ticket",   required_argument, NULL, 't'},
        {NULL,       no_argument,       NULL, '\0'}
    };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    bool res;
    unsigned long fileSize;
    unsigned flags = 0;
    while ((opt = getopt_long(argc, argv, "H:g:I:o:t:", long_options, NULL))
            != -1) {
        switch (opt) {
        case 'H':
            flags++;
            res = get_hierarchy_value(optarg, &ctx->hierarchyValue);
            if (!res) {
                return false;
            }
            break;
        case 'g':
            flags++;
            ctx->halg = tpm2_alg_util_from_optarg(optarg);
            if (ctx->halg == TPM_ALG_ERROR) {
                showArgError(optarg, argv[0]);
                return false;
            }
            break;
        case 'I':
            flags++;
            res = files_get_file_size(optarg, &fileSize);
            if (!res) {
                return false;
            }
            if (fileSize > MAX_DIGEST_BUFFER) {
                LOG_ERR(
                        "Input data too long: %lu, should be less than %d bytes\n",
                        fileSize, MAX_DIGEST_BUFFER);
                return false;
            }
            ctx->data.t.size = fileSize;
            res = files_load_bytes_from_file(optarg, ctx->data.t.buffer, &ctx->data.t.size);
            if (!res) {
                return false;
            }
            break;
        case 'o':
            flags++;
            ctx->outHashFilePath = optarg;
            res = files_does_file_exist(ctx->outHashFilePath);
            if (res) {
                return false;
            }
            break;
        case 't':
            flags++;
            ctx->outTicketFilePath = optarg;
            res = files_does_file_exist(ctx->outTicketFilePath);
            if (res) {
                return false;
            }
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??", opt);
            return false;
        }
    }

    /* all flags must be specified */
    if (flags != 5) {
        showArgMismatch(argv[0]);
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused, avoid compiler warning */
    (void)opts;
    (void)envp;

    tpm_hash_ctx ctx = {
            .sapi_context = sapi_context,
    };

    bool res = init(argc, argv, &ctx);
    if (!res) {
        return 1;
    }

    return hash_and_save(&ctx) != true;
}
