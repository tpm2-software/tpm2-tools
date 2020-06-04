/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

typedef struct tpm_activatecred_ctx tpm_activatecred_ctx;
struct tpm_activatecred_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } credential_key; //Typically EK

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } credentialed_key; //Typically AK

    TPM2B_ID_OBJECT credential_blob;
    TPM2B_ENCRYPTED_SECRET secret;
    const char *output_file;

    struct {
        UINT8 i :1;
        UINT8 o :1;
    } flags;

    char *cp_hash_path;
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
        LOG_ERR("Unknown credential format, got %"PRIu32" expected 1", version);
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

static tool_rc activate_credential_and_output(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_general_error;

    TPM2B_DIGEST *cert_info_data;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        rc = tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
            &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
            &cert_info_data, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    rc = tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
            &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
            &cert_info_data, NULL);
    if (rc != tool_rc_success) {
        goto out_all;
    }

    bool result = output_and_save(cert_info_data, ctx.output_file);
    if (!result) {
        goto out_all;
    }

    rc = tool_rc_success;

out_all:
    free(cert_info_data);
    return rc;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.credentialed_key.ctx_path = value;
        break;
    case 'p':
        ctx.credentialed_key.auth_str = value;
        break;
    case 'C':
        ctx.credential_key.ctx_path = value;
        break;
    case 'P':
        ctx.credential_key.auth_str = value;
        break;
    case 'i':
        /* logs errors */
        result = read_cert_secret(value, &ctx.credential_blob, &ctx.secret);
        if (!result) {
            return false;
        }
        ctx.flags.i = 1;
        break;
    case 'o':
        ctx.output_file = value;
        ctx.flags.o = 1;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
         {"credentialedkey-context", required_argument, NULL, 'c'},
         {"credentialkey-context",   required_argument, NULL, 'C'},
         {"credentialedkey-auth",    required_argument, NULL, 'p'},
         {"credentialkey-auth",      required_argument, NULL, 'P'},
         {"credential-blob",         required_argument, NULL, 'i'},
         {"certinfo-data",           required_argument, NULL, 'o'},
         {"cphash",                  required_argument, NULL,  0 },
    };

    *opts = tpm2_options_new("c:C:p:P:i:o:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    if ((!ctx.credentialed_key.ctx_path) && (!ctx.credential_key.ctx_path)
            && !ctx.flags.i && !ctx.flags.o) {
        LOG_ERR("Expected options c and C and i and o.");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.credential_key.ctx_path,
            ctx.credential_key.auth_str, &ctx.credential_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.credentialed_key.ctx_path,
            ctx.credentialed_key.auth_str, &ctx.credentialed_key.object,
            false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    return activate_credential_and_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    tool_rc rc = tool_rc_success;

    tool_rc tmp_rc = tpm2_session_close(&ctx.credentialed_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.credential_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("activatecredential", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
