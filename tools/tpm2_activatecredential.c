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
    /*
     * Inputs
     */
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
    const char *credential_blob_path;
    bool is_credential_blob_specified;
    TPM2B_ENCRYPTED_SECRET secret;

    /*
     * Outputs
     */
    const char *output_file;
    TPM2B_DIGEST *cert_info_data;

    /*
     * Parameter hashes
     */
    char *cp_hash_path;
    TPM2B_DIGEST *cphash;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
};

static tpm_activatecred_ctx ctx;

static tool_rc activate_credential_and_output(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    return tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
        &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
        &ctx.cert_info_data, ctx.cphash);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    tool_rc rc = ctx.cp_hash_path ? (files_save_digest(&ctx.cp_hash,
        ctx.cp_hash_path) ? tool_rc_success : tool_rc_general_error) :
        tool_rc_success;

    if (!ctx.is_command_dispatch || rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    tpm2_tool_output("certinfodata:");
    size_t i;
    for (i = 0; i < ctx.cert_info_data->size; i++) {
        tpm2_tool_output("%.2x", ctx.cert_info_data->buffer[i]);
    }
    tpm2_tool_output("\n");

    rc = files_save_bytes_to_file(ctx.output_file, ctx.cert_info_data->buffer,
        ctx.cert_info_data->size) ? tool_rc_success : tool_rc_general_error;
    free(ctx.cert_info_data);

    return rc;
}

static bool read_cert_secret(void) {

    bool result = false;
    FILE *fp = fopen(ctx.credential_blob_path, "rb");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"",
        ctx.credential_blob_path, strerror(errno));
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

    result = files_read_16(fp, &ctx.credential_blob.size);
    if (!result) {
        LOG_ERR("Could not read credential size");
        goto out;
    }

    result = files_read_bytes(fp, ctx.credential_blob.credential, ctx.credential_blob.size);
    if (!result) {
        LOG_ERR("Could not read credential data");
        goto out;
    }

    result = files_read_16(fp, &ctx.secret.size);
    if (!result) {
        LOG_ERR("Could not read secret size");
        goto out;
    }

    result = files_read_bytes(fp, ctx.secret.secret, ctx.secret.size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.credential_key.ctx_path,
        ctx.credential_key.auth_str, &ctx.credential_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }
    /* Object #2 */
    rc = tpm2_util_object_load_auth(ectx, ctx.credentialed_key.ctx_path,
        ctx.credentialed_key.auth_str, &ctx.credentialed_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    rc = read_cert_secret() ? tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    ctx.cphash = ctx.cp_hash_path ? &ctx.cp_hash : 0;

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(void) {

    if ((!ctx.credentialed_key.ctx_path) && (!ctx.credential_key.ctx_path)
        && !ctx.is_credential_blob_specified && !ctx.output_file) {
        LOG_ERR("Expected options c and C and i and o.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

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
        ctx.credential_blob_path = value;
        ctx.is_credential_blob_specified = 1;
        break;
    case 'o':
        ctx.output_file = value;
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

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = activate_credential_and_output(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.credentialed_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.credential_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("activatecredential", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
