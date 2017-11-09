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
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "tpm2_options.h"
#include "files.h"
#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_akparse_ctx tpm_akparse_ctx;
struct tpm_akparse_ctx {
    char *ak_data_file_path;
    char *ak_key_file_path;
};

static tpm_akparse_ctx ctx;

static bool save_alg_and_key_to_file(const char *key_file, UINT16 alg_type,
        TPM2B **key_data, size_t key_data_len) {

    FILE *f = fopen(key_file, "wb+");
    if (!f) {
        LOG_ERR("Could not open file \"%s\" due to error: \"%s\".", key_file,
                strerror(errno));
        return false;
    }

    bool res = files_write_16(f, alg_type);
    if (!res) {
        /* write_be_convert prints error */
        goto out;
    }

    /*
     * For each TPM2B buffer in the list, save its size in be format, write it
     * to the output file and output it to stdout.
     */
    unsigned i;
    for (i=0; i < key_data_len; i++) {
        TPM2B *tmp = key_data[i];

        res = files_write_16(f, tmp->size);
        if (!res) {
            /* write_be_convert prints error */
            goto out;
        }

        size_t count = fwrite(tmp->buffer, sizeof(BYTE), tmp->size, f);
        if (count != tmp->size) {
            if (ferror(f)) {
                LOG_ERR("Error writing to file \"%s\", error: \"%s\"", key_file,
                        strerror(errno));
            } else {
                LOG_ERR("Did not write all bytes to file, got %zu expected %u",
                        count, tmp->size);
            }
            goto out;
        }

        tpm2_util_print_tpm2b(tmp);
    }
out:
    fclose(f);

    return true;
}

static bool parse_and_save_ak_public() {

    TPM2B_PUBLIC outPublic;
    UINT16 size = sizeof(outPublic);

    bool result = files_load_bytes_from_path(ctx.ak_data_file_path, (UINT8 *)&outPublic, &size);
    if (!result) {
        /* loadDataFromFile prints error */
        return false;
    }

    size_t key_data_len = 1;
    TPM2B *key_data[2];
    switch (outPublic.publicArea.type) {
    case TPM_ALG_RSA:
        key_data[0] = (TPM2B *)&outPublic.publicArea.unique.rsa;
        break;
    case TPM_ALG_KEYEDHASH:
        key_data[0] = (TPM2B *)&outPublic.publicArea.unique.keyedHash;
        break;
    case TPM_ALG_SYMCIPHER:
        key_data[0] = (TPM2B *)&outPublic.publicArea.unique.sym;
        break;
    case TPM_ALG_ECC:
        key_data_len = 2;
        key_data[0] = (TPM2B *)&outPublic.publicArea.unique.ecc.x;
        key_data[1] = (TPM2B *)&outPublic.publicArea.unique.ecc.y;
        break;
    default:
        LOG_ERR("The algorithm type(0x%4.4x) is not supported",
                outPublic.publicArea.type);
        return false;
    }

    return save_alg_and_key_to_file(ctx.ak_key_file_path, outPublic.publicArea.type,
            key_data, key_data_len);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'f':
        ctx.ak_data_file_path = value;
        break;
    case 'k':
        ctx.ak_key_file_path = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
            { "file",    required_argument, NULL, 'f' },
            { "key-file", required_argument, NULL, 'k' },
    };

    *opts = tpm2_options_new("f:k:", ARRAY_LEN(topts), topts, on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(sapi_context);
    UNUSED(flags);

    /* 0 on success 1 on error */
    return parse_and_save_ak_public() != true;
}
