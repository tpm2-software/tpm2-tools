/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2
typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPM2_HANDLE nv_index;

    BYTE nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    FILE *input_file;
    UINT16 data_size;
    UINT16 offset;

    uint16_t max_data_size;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_nvwrite_ctx ctx = {
    .data_size = TPM2_MAX_NV_BUFFER_SIZE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
};

static tool_rc nv_write(ESYS_CONTEXT *ectx) {

    TPM2B_MAX_NV_BUFFER nv_write_data;
    UINT16 data_offset = 0;
    while (ctx.data_size > 0) {
        nv_write_data.size = ctx.data_size > ctx.max_data_size ?
            ctx.max_data_size : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.size);

        memcpy(nv_write_data.buffer, &ctx.nv_buffer[data_offset],
                nv_write_data.size);

        tool_rc rc = tpm2_nvwrite(ectx, &ctx.auth_hierarchy.object,
            ctx.nv_index, &nv_write_data, ctx.offset + data_offset,
            &ctx.cp_hash, &ctx.rp_hash, ctx.parameter_hash_algorithm,
            ctx.aux_session_handle[0], ctx.aux_session_handle[1]);
        if (rc != tool_rc_success) {
            return rc;
        }

        ctx.data_size -= nv_write_data.size;
        data_offset += nv_write_data.size;
    }

    return tool_rc_success;
}

static tool_rc process_output(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

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

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
        rc = is_file_op_success ? tool_rc_success : tool_rc_general_error;
    }

    return rc;
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle authorization");
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
    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC *nv_public = NULL;
    rc = tpm2_util_nv_read_public(ectx, ctx.nv_index, &nv_public);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to read NVRAM public area at index 0x%X",
                ctx.nv_index);

        free(nv_public);

        return tool_rc_general_error;
    }

    if (ctx.offset + ctx.data_size > nv_public->nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.", ctx.offset, ctx.data_size,
                nv_public->nvPublic.dataSize);

        free(nv_public);

        return tool_rc_option_error;
    }
    free(nv_public);

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
        ctx.aux_session[0],
        ctx.aux_session[1]
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

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    /*
     * Avoid overwritting cpHash
     */
    ctx.max_data_size = tpm2_nv_util_max_allowed_nv_size(ectx, false);
    if ((ctx.cp_hash_path || ctx.rp_hash_path) &&
    ctx.data_size > ctx.max_data_size) {
        LOG_ERR("Cannot calculate pHash for buffer larger than NV max buffer");
        return tool_rc_option_error;
    }

    if (!ctx.data_size) {
        LOG_ERR("Data to write is of size 0");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {
    /* If the user doesn't specify an authorization hierarchy use the index
     * as the authorization object.
     */
    if (!ctx.auth_hierarchy.ctx_path) {
        ctx.auth_hierarchy.ctx_path = argv[0];
    }
    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool on_option(char key, char *value) {

    char *input_file;

    switch (key) {

    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'i':
        input_file = strcmp("-", value) ? value : NULL;
        return files_load_bytes_from_buffer_or_file_or_stdin(NULL, input_file,
                &ctx.data_size, ctx.nv_buffer);
        break;
    case 0:
        if (!tpm2_util_string_to_uint16(value, &ctx.offset)) {
            LOG_ERR("Could not convert starting offset, got: \"%s\"", value);
            return false;
        }
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 2:
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

    const struct option topts[] = {
        { "hierarchy",            required_argument, NULL, 'C' },
        { "auth",                 required_argument, NULL, 'P' },
        { "input",                required_argument, NULL, 'i' },
        { "offset",               required_argument, NULL,  0  },
        { "cphash",               required_argument, NULL,  1  },
        { "rphash",               required_argument, NULL,  2  },
        { "session",              required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("C:P:i:S:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
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
    rc = nv_write(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx, flags);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);
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
TPM2_TOOL_REGISTER("nvwrite", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
