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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "tpm2_options.h"
#include "log.h"
#include "files.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_makecred_ctx tpm_makecred_ctx;
struct tpm_makecred_ctx {
    TPM2B_NAME object_name;
    char *out_file_path;
    TPM2B_PUBLIC public;
    TPM2B_DIGEST credential;
    struct {
        UINT8 e : 1;
        UINT8 s : 1;
        UINT8 n : 1;
        UINT8 o : 1;
    } flags;
};

static tpm_makecred_ctx ctx = {
    .object_name = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .credential = TPM2B_EMPTY_INIT,
};

static bool write_cred_and_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;

    FILE *fp = fopen(path, "wb+");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    result = files_write_header(fp, 1);
    if (!result) {
        LOG_ERR("Could not write version header");
        goto out;
    }

    result = files_write_16(fp, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential size");
        goto out;
    }

    result = files_write_bytes(fp, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential data");
        goto out;
    }

    result = files_write_16(fp, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret size");
        goto out;
    }

    result = files_write_bytes(fp, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static bool make_credential_and_save(ESYS_CONTEXT *ectx)
{
    TPM2B_ID_OBJECT *cred_blob;
    TPM2B_ENCRYPTED_SECRET *secret;
    ESYS_TR tr_handle = ESYS_TR_NONE;
    UINT32 rval;

    rval = Esys_LoadExternal(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                        ESYS_TR_NONE, NULL, &ctx.public, TPM2_RH_NULL,
                        &tr_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_LoadExternal, rval);
        return false;
    }

    rval = Esys_MakeCredential(ectx, tr_handle, ESYS_TR_NONE,
                        ESYS_TR_NONE, ESYS_TR_NONE, &ctx.credential,
                        &ctx.object_name, &cred_blob, &secret);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_MakeCredential, rval);
        return false;
    }

    rval = Esys_FlushContext(ectx, tr_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_FlushContext, rval);
        return false;
    }

    bool ret = write_cred_and_secret(ctx.out_file_path, cred_blob, secret);
    free(cred_blob);
    free(secret);
    return ret;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'e': {
        bool res = files_load_public(value, &ctx.public);
        if (!res) {
            return false;
        }
        ctx.flags.e = 1;
    } break;
    case 's':
        ctx.credential.size = BUFFER_SIZE(TPM2B_DIGEST, buffer);
        if (!files_load_bytes_from_path(value, ctx.credential.buffer,
                                        &ctx.credential.size)) {
            return false;
        }
        ctx.flags.s = 1;
        break;
    case 'n': {
        ctx.object_name.size = BUFFER_SIZE(TPM2B_NAME, name);
        int q;
        if ((q = tpm2_util_hex_to_byte_structure(value, &ctx.object_name.size,
                                            ctx.object_name.name)) != 0) {
            LOG_ERR("FAILED: %d", q);
            return false;
        }
        ctx.flags.n = 1;
    } break;
    case 'o':
        ctx.out_file_path = value;
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"enc-key"  ,required_argument, NULL, 'e'},
      {"secret"   ,required_argument, NULL, 's'},
      {"name"     ,required_argument, NULL, 'n'},
      {"out-file" ,required_argument, NULL, 'o'},
    };

    *opts = tpm2_options_new("e:s:n:o:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.flags.e || !ctx.flags.n || !ctx.flags.o || !ctx.flags.s) {
        LOG_ERR("Expected options e, n, o and s.");
        return -11;
    }

    return make_credential_and_save(ectx) != true;
}
