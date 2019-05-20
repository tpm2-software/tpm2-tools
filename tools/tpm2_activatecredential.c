/* SPDX-License-Identifier: BSD-3-Clause */

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
    } flags;

    struct {
        char *auth_str;
        tpm2_session *session;
        const char *ctx_arg;
    } key;

    struct {
        char *auth_str;
        tpm2_session *session;
    } endorse;

    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;

    const char *output_file;
    const char *ctx_arg;
    tpm2_loaded_object ctx_obj;
    tpm2_loaded_object key_ctx_obj;
};

static tpm_activatecred_ctx ctx;

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

    bool retval = false;

    TPM2B_DIGEST *certInfoData;

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_open(ectx, d);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    // Set session up
    ESYS_TR sess_handle = tpm2_session_get_handle(session);

    ESYS_TR endorse_shandle = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_ENDORSEMENT,
                                ctx.endorse.session);
    if (endorse_shandle == ESYS_TR_NONE) {
        goto out_session;
    }

    TSS2_RC rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle,
                    endorse_shandle, ESYS_TR_NONE, ESYS_TR_NONE,
                    NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        goto out_session;
    }

    ESYS_TR key_shandle = tpm2_auth_util_get_shandle(ectx,
                            ctx.ctx_obj.tr_handle,
                            ctx.key.session);
    if (key_shandle == ESYS_TR_NONE) {
        goto out_session;
    }

    rval = Esys_ActivateCredential(ectx, ctx.ctx_obj.tr_handle,
            ctx.key_ctx_obj.tr_handle,
            key_shandle, sess_handle, ESYS_TR_NONE,
            &ctx.credentialBlob, &ctx.secret, &certInfoData);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ActivateCredential, rval);
        goto out_all;
    }

    retval = output_and_save(certInfoData, ctx.output_file);

out_all:
    free(certInfoData);
out_session:
    tpm2_session_close(&session);

    return retval;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.ctx_arg = value;
        break;
    case 'C':
        ctx.key.ctx_arg = value;
        break;
    case 'P':
        ctx.key.auth_str = value;
        break;
    case 'E':
        ctx.endorse.auth_str = value;
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

    int rc = 1;

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    if ((!ctx.ctx_arg)
            && (!ctx.key.ctx_arg)
            && !ctx.flags.i && !ctx.flags.o) {
        LOG_ERR("Expected options c and C and i and o.");
        return -1;
    }

    bool res = tpm2_util_object_load(ectx, ctx.ctx_arg,
                                &ctx.ctx_obj);
    if (!res) {
        return 1;
    }

    res = tpm2_util_object_load(ectx, ctx.key.ctx_arg,
                &ctx.key_ctx_obj);
    if (!res) {
        return 1;
    }

    res = tpm2_auth_util_from_optarg(ectx, ctx.key.auth_str,
            &ctx.key.session, false);
    if (!res) {
        LOG_ERR("Invalid handle authorization, got\"%s\"", ctx.key.auth_str);
        return 1;
    }

    res = tpm2_auth_util_from_optarg(NULL, ctx.endorse.auth_str,
            &ctx.endorse.session, true);
    if (!res) {
        LOG_ERR("Invalid endorse authorization, got\"%s\"", ctx.endorse.auth_str);
        goto out;
    }

    res = activate_credential_and_output(ectx);
    if (!res) {
        goto out;
    }

    rc = 0;

out:
    res = tpm2_session_close(&ctx.key.session);
    if (!res) {
        rc = 1;
    }

    res = tpm2_session_close(&ctx.endorse.session);
    if (!res) {
        rc = 1;
    }

    return rc;
}
