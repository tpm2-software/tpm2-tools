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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_hierarchy.h"

typedef struct tpm_hash_ctx tpm_hash_ctx;
struct tpm_hash_ctx {
    TPMI_RH_HIERARCHY hierarchyValue;
    FILE *input_file;
    TPMI_ALG_HASH  halg;
    char *outHashFilePath;
    char *outTicketFilePath;
};

static tpm_hash_ctx ctx = {
    .hierarchyValue = TPM2_RH_OWNER,
    .halg = TPM2_ALG_SHA1,
};

static bool hash_and_save(ESYS_CONTEXT *context) {

    TPM2B_DIGEST *outHash;
    TPMT_TK_HASHCHECK *validation;

    bool res = tpm2_hash_file(context, ctx.halg, ctx.hierarchyValue,
                              ctx.input_file, &outHash, &validation);
    if (!res) {
        return false;
    }

    if (outHash->size) {
        UINT16 i;
        tpm2_tool_output("%s: ", tpm2_alg_util_algtostr(ctx.halg,
                tpm2_alg_util_flags_hash));
        for (i = 0; i < outHash->size; i++) {
            tpm2_tool_output("%02x", outHash->buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    if (validation->digest.size) {
        UINT16 i;
        tpm2_tool_output("ticket:");
        for (i = 0; i < validation->digest.size; i++) {
            tpm2_tool_output("%02x", validation->digest.buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    if (ctx.outHashFilePath) {
        bool result = files_save_bytes_to_file(ctx.outHashFilePath,
                                               &outHash->buffer[0],
                                               outHash->size);
        if (!result) {
            return false;
        }
    }

    if (ctx.outTicketFilePath) {
        bool result = files_save_validation(validation, ctx.outTicketFilePath);
        if (!result) {
            return false;
        }
    }

    free(outHash);
    free(validation);

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one hash input file, got: %d", argc);
        return false;
    }

    ctx.input_file = fopen(argv[0], "rb");
    if (!ctx.input_file) {
        LOG_ERR("Could not open input file \"%s\", error: %s",
                argv[0], strerror(errno));
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool res;
    switch (key) {
    case 'a':
        res = tpm2_hierarchy_from_optarg(value, &ctx.hierarchyValue,
                TPM2_HIERARCHY_FLAGS_ALL);
        if (!res) {
            return false;
        }
        break;
    case 'G':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            return false;
        }
        break;
    case 'o':
        ctx.outHashFilePath = value;
        break;
    case 't':
        ctx.outTicketFilePath = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        {"hierarchy", required_argument, NULL, 'a'},
        {"halg",      required_argument, NULL, 'G'},
        {"out-file",  required_argument, NULL, 'o'},
        {"ticket",    required_argument, NULL, 't'},
    };

    /* set up non-static defaults here */
    ctx.input_file = stdin;

    *opts = tpm2_options_new("a:G:o:t:", ARRAY_LEN(topts), topts, on_option,
                             on_args, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;

    bool res = hash_and_save(context);
    if (!res) {
        goto out;
    }

    rc = 0;

out:
    if (ctx.input_file) {
        fclose(ctx.input_file);
    }

    return rc;
}
