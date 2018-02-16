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

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_hash_ctx tpm_hash_ctx;
struct tpm_hash_ctx {
    TPMI_RH_HIERARCHY hierarchyValue;
    FILE *input_file;
    TPMI_ALG_HASH  halg;
    char *outHashFilePath;
    char *outTicketFilePath;
};

static tpm_hash_ctx ctx = {
    .hierarchyValue = TPM2_RH_NULL,
    .halg = TPM2_ALG_SHA1,
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
        *hierarchy_value = TPM2_RH_ENDORSEMENT;
        break;
    case 'o':
        *hierarchy_value = TPM2_RH_OWNER;
        break;
    case 'p':
        *hierarchy_value = TPM2_RH_PLATFORM;
        break;
    case 'n':
        *hierarchy_value = TPM2_RH_NULL;
        break;
    default:
        LOG_ERR("Unknown hierarchy value: %s", hiearchy_code);
        return false;
    }
    return true;
}

static bool hash_and_save(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_DIGEST outHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_HASHCHECK validation;

    bool res = tpm2_hash_file(sapi_context, ctx.halg, ctx.hierarchyValue, ctx.input_file, &outHash, &validation);
    if (!res) {
        return false;
    }

    if (outHash.size) {
        UINT16 i;
        tpm2_tool_output("%s: ", tpm2_alg_util_algtostr(ctx.halg));
        for (i = 0; i < outHash.size; i++) {
            tpm2_tool_output("%02x", outHash.buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    if (validation.digest.size) {
        UINT16 i;
        tpm2_tool_output("ticket:");
        for (i = 0; i < validation.digest.size; i++) {
            tpm2_tool_output("%02x", validation.digest.buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    if (ctx.outHashFilePath) {
        bool result = files_save_bytes_to_file(ctx.outHashFilePath, outHash.buffer,
                outHash.size);
        if (!result) {
            return false;
        }
    }

    if (ctx.outTicketFilePath) {
        return files_save_validation(&validation, ctx.outTicketFilePath);
    }

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
    case 'H':
        res = get_hierarchy_value(value, &ctx.hierarchyValue);
        if (!res) {
            return false;
        }
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value);
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
        {"hierarchy", required_argument, NULL, 'H'},
        {"halg",      required_argument, NULL, 'g'},
        {"out-file",  required_argument, NULL, 'o'},
        {"ticket",    required_argument, NULL, 't'},
    };

    /* set up non-static defaults here */
    ctx.input_file = stdin;

    *opts = tpm2_options_new("H:g:o:t:", ARRAY_LEN(topts), topts, on_option,
                             on_args, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;

    bool res = hash_and_save(sapi_context);
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
