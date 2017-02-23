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
#include <getopt.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "files.h"
#include "main.h"
#include "options.h"
#include "string-bytes.h"

typedef struct tpm_makecred_ctx tpm_makecred_ctx;
struct tpm_makecred_ctx {
    TPM_HANDLE rsa2048_handle;
    TPM2B_NAME object_name;
    char out_file_path[PATH_MAX];
    TPM2B_PUBLIC public;
    TPM2B_DIGEST credential;
};

static bool write_cred_and_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;

    FILE *fp = fopen(path, "w+");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    size_t items = fwrite(cred, sizeof(TPM2B_ID_OBJECT), 1, fp);
    if (items != 1) {
        LOG_ERR("writing credential to file \"%s\" failed, error: \"%s\"", path,
                strerror(errno));
        goto out;
    }

    items = fwrite(secret, sizeof(TPM2B_ENCRYPTED_SECRET), 1, fp);
    if (items != 1) {
        LOG_ERR("writing secret to file \"%s\" failed, error: \"%s\"", path,
                strerror(errno));
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static bool make_credential_and_save(TSS2_SYS_CONTEXT *sapi_context, tpm_makecred_ctx *ctx)
{
    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_RESPONSE *session_data_out_array[1];

    TPM2B_NAME name_ext = {
            { sizeof(TPM2B_NAME)-2, }
    };

    TPM2B_ID_OBJECT cred_blob = {
            { sizeof(TPM2B_ID_OBJECT)-2, }
    };

    TPM2B_ENCRYPTED_SECRET secret = {
            { sizeof(TPM2B_ENCRYPTED_SECRET)-2, }
    };

    session_data_out_array[0] = &session_data_out;
    sessions_data_out.rspAuths = &session_data_out_array[0];
    sessions_data_out.rspAuthsCount = 1;

    UINT32 rval = Tss2_Sys_LoadExternal(sapi_context, 0, NULL, &ctx->public,
            TPM_RH_NULL, &ctx->rsa2048_handle, &name_ext, &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("LoadExternal failed. TPM Error:0x%x", rval);
        return false;
    }

    rval = Tss2_Sys_MakeCredential(sapi_context, ctx->rsa2048_handle, 0,
            &ctx->credential, &ctx->object_name, &cred_blob, &secret,
            &sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("MakeCredential failed. TPM Error:0x%x", rval);
        return false;
    }

    rval = Tss2_Sys_FlushContext(sapi_context, ctx->rsa2048_handle);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("Flush loaded key failed. TPM Error:0x%x", rval);
        return false;
    }

    return write_cred_and_secret(ctx->out_file_path, &cred_blob, &secret);
}

static bool init(int argc, char *argv[], tpm_makecred_ctx *ctx) {

    static const char *optstring = "e:s:n:o:";
    static const struct option long_options[] = {
      {"encKey"  ,required_argument, NULL, 'e'},
      {"sec"     ,required_argument, NULL, 's'},
      {"name"    ,required_argument, NULL, 'n'},
      {"outFile" ,required_argument, NULL, 'o'},
      {NULL      ,no_argument      , NULL, '\0'}
    };

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    UINT16 size;
    int flagCnt = 0;
    int opt = -1;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'e':
            size = sizeof(ctx->public);
            if (loadDataFromFile(optarg, (UINT8 *) &ctx->public, &size) != 0) {
                return false;
            }
            flagCnt++;
            break;
        case 's':
            ctx->credential.t.size = sizeof(ctx->credential) - 2;
            if (loadDataFromFile(optarg, ctx->credential.t.buffer,
                    &ctx->credential.t.size) != 0) {
                return false;
            }
            flagCnt++;
            break;
        case 'n':
            ctx->object_name.t.size = sizeof(ctx->object_name) - 2;
            if (hex2ByteStructure(optarg, &ctx->object_name.t.size,
                    ctx->object_name.t.name) != 0) {
                return false;
            }
            flagCnt++;
            break;
        case 'o':
            snprintf(ctx->out_file_path, sizeof(ctx->out_file_path), "%s",
                    optarg);
            if (checkOutFile(ctx->out_file_path) != 0) {
                return false;
            }
            flagCnt++;
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

    if (flagCnt != 4) {
        showArgMismatch(argv[0]);
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused, avoid compiler warning */
    (void) opts;

    tpm_makecred_ctx ctx = { 0 };
    bool result = init(argc, argv, &ctx);
    if (!result) {
        LOG_ERR("Initialization failed");
        return 1;
    }

    return make_credential_and_save(sapi_context, &ctx) != true;
}
