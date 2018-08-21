//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_error.h"
#include "tpm2_options.h"
#include "tpm2_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"

typedef struct tpm_activatecred_ctx tpm_activatecred_ctx;
struct tpm_activatecred_ctx {

    struct {
        UINT8 f : 1;
        UINT8 o : 1;
        UINT8 P : 1;
        UINT8 E : 1;
    } flags;

    char *passwd_auth_str;
    char *endorse_auth_str;

    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;

    TPMS_AUTH_COMMAND auth;
    tpm2_session *auth_session;

    TPMS_AUTH_COMMAND endorse_auth;
    tpm2_session *endorse_session;

    const char *output_file;
    const char *ctx_arg;
    const char *key_ctx_arg;
    tpm2_loaded_object ctx_obj;
    tpm2_loaded_object key_ctx_obj;
};

static tpm_activatecred_ctx ctx = {
        .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .endorse_auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
};

static bool read_cert_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    uint32_t version;
    result = files_read_header(fp, &version);
    if (!result) {
        LOG_ERR("Could not read version header");
        goto out;
    }

    if (version != 1) {
        LOG_ERR("Unknown credential format, got %"PRIu32" expected 1",
                version);
        goto out;
    }

    result = files_read_16(fp, &cred->size);
    if (!result) {
        LOG_ERR("Could not read credential size");
        goto out;
    }

    result = files_read_bytes(fp, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not read credential data");
        goto out;
    }

    result = files_read_16(fp, &secret->size);
    if (!result) {
        LOG_ERR("Could not read secret size");
        goto out;
    }

    result = files_read_bytes(fp, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static bool output_and_save(TPM2B_DIGEST *digest, const char *path) {

    tpm2_tool_output("certinfodata:");

    unsigned k;
    for (k = 0; k < digest->size; k++) {
        tpm2_tool_output("%.2x", digest->buffer[k]);
    }
    tpm2_tool_output("\n");

    return files_save_bytes_to_file(path, digest->buffer, digest->size);
}

static bool activate_credential_and_output(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_DIGEST certInfoData = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TSS2L_SYS_AUTH_COMMAND cmd_auth_array_password = {
        2, {
            ctx.auth,
            TPMS_AUTH_COMMAND_INIT(0),
        }
    };

    TSS2L_SYS_AUTH_COMMAND cmd_auth_array_endorse = {
        1, {
            ctx.endorse_auth
        }
    };

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_new(sapi_context, d);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(session);


    TPM2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM2_RH_ENDORSEMENT,
            handle, &cmd_auth_array_endorse, 0, 0, 0, 0, 0, 0, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicySecret, rval);
        return false;
    }

    cmd_auth_array_password.auths[1].sessionHandle = handle;
    cmd_auth_array_password.auths[1].sessionAttributes |= 
            TPMA_SESSION_CONTINUESESSION;
    cmd_auth_array_password.auths[1].hmac.size = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_ActivateCredential(sapi_context, ctx.ctx_obj.handle,
            ctx.key_ctx_obj.handle, &cmd_auth_array_password, &ctx.credentialBlob, &ctx.secret,
            &certInfoData, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ActivateCredential, rval);
        return false;
    }

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }

    tpm2_session_free(&session);

    return output_and_save(&certInfoData, ctx.output_file);
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.ctx_arg = value;
        break;
    case 'C':
        ctx.key_ctx_arg = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.passwd_auth_str = value;
        break;
    case 'E':
        ctx.flags.E = 1;
        ctx.endorse_auth_str = value;
        break;
    case 'f':
        /* logs errors */
        result = read_cert_secret(value, &ctx.credentialBlob,
                &ctx.secret);
        if (!result) {
            return false;
        }
        ctx.flags.f = 1;
        break;
    case 'o':
        ctx.output_file = value;
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
         {"context",        required_argument, NULL, 'c'},
         {"key-context",    required_argument, NULL, 'C'},
         {"auth-key",       required_argument, NULL, 'P'},
         {"auth-endorse",   required_argument, NULL, 'E'},
         {"in-file",        required_argument, NULL, 'f'},
         {"out-file",       required_argument, NULL, 'o'},
    };

    *opts = tpm2_options_new("c:C:P:E:f:o:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    if ((!ctx.ctx_arg)
            && (!ctx.key_ctx_arg)
            && !ctx.flags.f && !ctx.flags.o) {
        LOG_ERR("Expected options c and C and f and o.");
        return -1;
    }

    bool res = tpm2_util_object_load_sapi(sapi_context, ctx.ctx_arg,
                    &ctx.ctx_obj);
    if (!res) {
        return 1;
    }

    res = tpm2_util_object_load_sapi(sapi_context, ctx.key_ctx_arg,
                &ctx.key_ctx_obj);
    if (!res) {
        return 1;
    }

    if (ctx.flags.P) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.passwd_auth_str,
                &ctx.auth, &ctx.auth_session);
        if (!res) {
            LOG_ERR("Invalid handle authorization, got\"%s\"", ctx.passwd_auth_str);
            return 1;
        }
    }

    if (ctx.flags.E) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.endorse_auth_str,
                &ctx.endorse_auth, &ctx.endorse_session);
        if (!res) {
            LOG_ERR("Invalid endorse authorization, got\"%s\"", ctx.endorse_auth_str);
            return 1;
        }
    }

    int rc = 0;
    res = activate_credential_and_output(sapi_context);
    if (!res) {
        rc = 1;
        goto out;
    }

out:

    if (ctx.auth_session) {
        res = tpm2_session_save(sapi_context, ctx.auth_session, NULL);
        if (!res) {
            rc = 1;
        }

        tpm2_session_free(&ctx.auth_session);
    }

    if (ctx.endorse_session) {
        res = tpm2_session_save(sapi_context, ctx.endorse_session, NULL);
        if (!res) {
            rc = 1;
        }

        tpm2_session_free(&ctx.endorse_session);
    }

    return rc;
}
