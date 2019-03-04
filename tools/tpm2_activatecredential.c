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

#include <tss2/tss2_esys.h>

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
        UINT8 i : 1;
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

static bool activate_credential_and_output(ESYS_CONTEXT *ectx) {

    TPM2B_DIGEST *certInfoData;

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_new(ectx, d);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    // Set session up
    ESYS_TR sess_handle = tpm2_session_get_handle(session);
    tpm2_session_free(&session);

    ESYS_TR endorse_shandle = tpm2_auth_util_get_shandle(ectx, sess_handle,
                                &ctx.endorse_auth, ctx.endorse_session);
    if (endorse_shandle == ESYS_TR_NONE) {
        return false;
    }

    TSS2_RC rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle,
                    endorse_shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        return false;
    }

    ESYS_TR key_shandle = tpm2_auth_util_get_shandle(ectx,
                            ctx.key_ctx_obj.tr_handle, &ctx.auth,
                            ctx.auth_session);
    if (key_shandle == ESYS_TR_NONE) {
        return false;
    }

    bool retval = true;
    // NOTE: key_shandle and sess_handle don't seem to match docs
    rval = Esys_ActivateCredential(ectx, ctx.ctx_obj.tr_handle,
            ctx.key_ctx_obj.tr_handle,
            key_shandle, sess_handle, ESYS_TR_NONE,
            &ctx.credentialBlob, &ctx.secret, &certInfoData);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ActivateCredential, rval);
        retval = false;
        goto out;
    }

    // Need to flush the session here.
    rval = Esys_FlushContext(ectx, sess_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_FlushContext, rval);
        retval = false;
        goto out;
    }

    retval = output_and_save(certInfoData, ctx.output_file);

out:
    free(certInfoData);

    return retval;
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
    case 'i':
        /* logs errors */
        result = read_cert_secret(value, &ctx.credentialBlob,
                &ctx.secret);
        if (!result) {
            return false;
        }
        ctx.flags.i = 1;
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
         {"in-file",        required_argument, NULL, 'i'},
         {"out-file",       required_argument, NULL, 'o'},
    };

    *opts = tpm2_options_new("c:C:P:E:i:o:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    if ((!ctx.ctx_arg)
            && (!ctx.key_ctx_arg)
            && !ctx.flags.i && !ctx.flags.o) {
        LOG_ERR("Expected options c and C and i and o.");
        return -1;
    }

    bool res;
    tpm2_object_load_rc olrc = tpm2_util_object_load(ectx, ctx.ctx_arg,
                                &ctx.ctx_obj);
    if (olrc == olrc_error) {
        return 1;
    } else if (!ctx.ctx_obj.tr_handle) {
        res = tpm2_util_sys_handle_to_esys_handle(ectx, ctx.ctx_obj.handle,
                &ctx.ctx_obj.tr_handle);
        if (!res) {
            return 1;
        }
    }

    olrc = tpm2_util_object_load(ectx, ctx.key_ctx_arg,
                &ctx.key_ctx_obj);
    if (olrc == olrc_error) {
        return 1;
    } else if (!ctx.key_ctx_obj.tr_handle) {
        res = tpm2_util_sys_handle_to_esys_handle(ectx, ctx.key_ctx_obj.handle,
                &ctx.key_ctx_obj.tr_handle);
        if (!res) {
            return 1;
        }
    }

    if (ctx.flags.P) {
        res = tpm2_auth_util_from_optarg(ectx, ctx.passwd_auth_str,
                &ctx.auth, &ctx.auth_session);
        if (!res) {
            LOG_ERR("Invalid handle authorization, got\"%s\"", ctx.passwd_auth_str);
            return 1;
        }
    }

    if (ctx.flags.E) {
        res = tpm2_auth_util_from_optarg(ectx, ctx.endorse_auth_str,
                &ctx.endorse_auth, &ctx.endorse_session);
        if (!res) {
            LOG_ERR("Invalid endorse authorization, got\"%s\"", ctx.endorse_auth_str);
            return 1;
        }
    }

    int rc = 0;
    res = activate_credential_and_output(ectx);
    if (!res) {
        rc = 1;
        goto out;
    }

out:

    if (ctx.auth_session) {
        res = tpm2_session_save(ectx, ctx.auth_session, NULL);
        if (!res) {
            rc = 1;
        }

        tpm2_session_free(&ctx.auth_session);
    }

    if (ctx.endorse_session) {
        res = tpm2_session_save(ectx, ctx.endorse_session, NULL);
        if (!res) {
            rc = 1;
        }

        tpm2_session_free(&ctx.endorse_session);
    }

    return rc;
}
