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
#define MAX_AUX_SESSIONS 1 // two sessions provided by auth interface
#define MAX_SESSIONS 3
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
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    TPMI_ALG_HASH parameter_hash_algorithm;
    bool is_command_dispatch;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_activatecred_ctx ctx = {
    .aux_session_handle[0] = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc activate_credential_and_output(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    return tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
        &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
        &ctx.cert_info_data, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0]);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
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

    is_file_op_success = files_save_bytes_to_file(ctx.output_file,
        ctx.cert_info_data->buffer, ctx.cert_info_data->size);
    free(ctx.cert_info_data);
    if (!is_file_op_success) {
        return tool_rc_general_error;
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
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
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }

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
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.credential_key.object.session,
        ctx.credentialed_key.object.session,
        ctx.aux_session[0]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

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
    case 1:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
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
         {"rphash",                  required_argument, NULL,  1 },
         {"session",                required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("c:C:p:P:i:o:S:", ARRAY_LEN(topts), topts, on_option,
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
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("activatecredential", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
