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
        UINT8 H : 1;
        UINT8 c : 1;
        UINT8 k : 1;
        UINT8 C : 1;
        UINT8 f : 1;
        UINT8 o : 1;
        UINT8 P : 1;
        UINT8 e : 1;
    } flags;

    char *passwd_auth_str;
    char *endorse_auth_str;

    struct {
        TPMI_DH_OBJECT activate;
        TPMI_DH_OBJECT key;
    } handle;

    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;

    TPMS_AUTH_COMMAND auth;
    tpm2_session *auth_session;

    TPMS_AUTH_COMMAND endorse_auth;
    tpm2_session *endorse_session;

    struct {
        char *output;
        char *context;
        char *key_context;
    } file ;
};

static tpm_activatecred_ctx ctx = {
        .auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .endorse_auth = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW)
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

    rval = TSS2_RETRY_EXP(Tss2_Sys_ActivateCredential(sapi_context, ctx.handle.activate,
            ctx.handle.key, &cmd_auth_array_password, &ctx.credentialBlob, &ctx.secret,
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

    return output_and_save(&certInfoData, ctx.file.output);
}

static bool on_option(char key, char *value) {

    bool result;
    switch (key) {
    case 'H':
        result = tpm2_util_string_to_uint32(value, &ctx.handle.activate);
        if (!result) {
            LOG_ERR("Could not convert -H argument to a number, "
                    "got \"%s\"!", value);
            return false;
        }
        ctx.flags.H = 1;
        break;
    case 'c':
        ctx.file.context = value;
        ctx.flags.c = 1;
        break;
    case 'k':
        result = tpm2_util_string_to_uint32(value, &ctx.handle.key);
        if (!result) {
            return false;
        }
        ctx.flags.k = 1;
        break;
    case 'C':
        ctx.file.key_context = value;
        ctx.flags.C = 1;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.passwd_auth_str = value;
        break;
    case 'e':
        ctx.flags.e = 1;
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
        ctx.file.output = value;
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
         {"handle",         required_argument, NULL, 'H'},
         {"context",        required_argument, NULL, 'c'},
         {"key-handle",     required_argument, NULL, 'k'},
         {"key-context",    required_argument, NULL, 'C'},
         {"Password",       required_argument, NULL, 'P'},
         {"endorse-passwd", required_argument, NULL, 'e'},
         {"in-file",        required_argument, NULL, 'f'},
         {"out-file",       required_argument, NULL, 'o'},
         {"passwdInHex",    no_argument,       NULL, 'X'},
    };

    *opts = tpm2_options_new("H:c:k:C:P:e:f:o:X", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    if ((!ctx.flags.H && !ctx.flags.c)
            && (!ctx.flags.k || !ctx.flags.C) && !ctx.flags.f
            && !ctx.flags.o) {
        LOG_ERR("Expected options (H or c) and (k or C) and f and o");
        return 1;
    }

    if (ctx.file.context) {
        bool res = files_load_tpm_context_from_path(sapi_context, &ctx.handle.activate,
                ctx.file.context);
        if (!res) {
            return 1;
        }
    }

    if (ctx.file.key_context) {
        bool res = files_load_tpm_context_from_path(sapi_context, &ctx.handle.key,
                ctx.file.key_context) != true;
        if (!res) {
            return 1;
        }
    }

    if (ctx.flags.P) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.passwd_auth_str,
                &ctx.auth, &ctx.auth_session);
        if (!res) {
            LOG_ERR("Invalid handle authorization, got\"%s\"", ctx.passwd_auth_str);
            return 1;
        }
    }

    if (ctx.flags.e) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.endorse_auth_str,
                &ctx.endorse_auth, &ctx.endorse_session);
        if (!res) {
            LOG_ERR("Invalid endorse authorization, got\"%s\"", ctx.endorse_auth_str);
            return 1;
        }
    }

    int rc = 0;
    bool res = activate_credential_and_output(sapi_context);
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
