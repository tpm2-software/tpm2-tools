/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"


typedef struct tpm_nvextend_ctx tpm_nvextend_ctx;
#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2
struct tpm_nvextend_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    const char *input_path;
    TPM2_HANDLE nv_index;
    TPM2B_NAME precalc_nvname;
    TPM2B_MAX_NV_BUFFER data;

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
    bool is_tcti_none;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_nvextend_ctx ctx = {
    .data.size = sizeof(ctx.data.buffer),
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc nvextend(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    return tpm2_nvextend(ectx, &ctx.auth_hierarchy.object, ctx.nv_index,
        &ctx.data, &ctx.cp_hash, &ctx.rp_hash, ctx.parameter_hash_algorithm,
        &ctx.precalc_nvname, ctx.aux_session_handle[0],
        ctx.aux_session_handle[1]);
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
    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
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
    tool_rc rc = tool_rc_success;
    if (ctx.is_tcti_none) {
        /*
         * Cannot use tpm2_util_object_load like in nvdefine as it makes a call
         * to tpm2_util_sys_handle_to_esys_handle which then tries to read the
         * ESYS_TR object off of the TPM expecting it to be there.
         * Note: this if it is a permanent handle ESYS_TR is fixed and so the
         * TPM is not probed even with tpm2_util_sys_handle_to_esys_handle.
         */
        rc = tpm2_util_handle_from_optarg(ctx.auth_hierarchy.ctx_path,
            &ctx.auth_hierarchy.object.handle,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P) ?
        tool_rc_success : tool_rc_option_error;

         ctx.auth_hierarchy.object.tr_handle = (rc == tool_rc_success) ?
            tpm2_tpmi_hierarchy_to_esys_tr(ctx.auth_hierarchy.object.handle) : 0;
    } else {
        rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_NV | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    }

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
     * 3. Command specific initializations dependent on loaded objects
     */
    ctx.input_path = strcmp(ctx.input_path, "-") ? ctx.input_path : NULL;

    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.input_path, &ctx.data.size, ctx.data.buffer);
    if (!result) {
        return tool_rc_general_error;
    }
    /*
     * 4. Configuration for calculating the pHash
     */

    /* 4.a Determine pHash length and alg */
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
     * is_tcti_none       [N]
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.is_tcti_none ||
        (ctx.cp_hash_path && !ctx.rp_hash_path)) ? false : true;

    return rc;
}

static tool_rc check_options(tpm2_option_flags flags) {

    ctx.is_tcti_none = flags.tcti_none ? true : false;
    if (ctx.is_tcti_none && !ctx.cp_hash_path) {
        LOG_ERR("If tcti is none, then cpHash path must be specified");
        return tool_rc_option_error;
    }

    bool is_nv_name_specified = ctx.precalc_nvname.size;
    if (ctx.is_tcti_none && !is_nv_name_specified) {
        LOG_ERR("Must specify the NVIndex name.");
        return tool_rc_option_error;
    }

    if (!ctx.is_tcti_none && is_nv_name_specified) {
        LOG_ERR("Do not specify NVIndex name, it is directly read from NV");
        return tool_rc_option_error;
    }

    if (!ctx.input_path) {
        LOG_ERR("Must specify source of data to write to NV index");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {

    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'i':
        ctx.input_path = value;
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
            return false;
        }
        break;
    case 'n':
        ctx.precalc_nvname.size = BUFFER_SIZE(TPM2B_NAME, name);
        int q = tpm2_util_hex_to_byte_structure(value, &ctx.precalc_nvname.size,
        ctx.precalc_nvname.name);
        if (q) {
            LOG_ERR("FAILED: %d", q);
            return false;
        }
        break;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {
    /*
     * If the user doesn't specify an authorization hierarchy use the index.
     */
    if (!ctx.auth_hierarchy.ctx_path) {
        ctx.auth_hierarchy.ctx_path = argv[0];
    }

    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'C' },
        { "auth",      required_argument, NULL, 'P' },
        { "input",     required_argument, NULL, 'i' },
        { "cphash",    required_argument, NULL,  0  },
        { "rphash",    required_argument, NULL,  1  },
        { "session",   required_argument, NULL, 'S' },
        { "name",      required_argument, NULL, 'n' },
    };

    *opts = tpm2_options_new("S:C:P:i:n:", ARRAY_LEN(topts), topts, on_option,
            on_arg, TPM2_OPTIONS_FAKE_TCTI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(flags);
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
    rc = nvextend(ectx);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */
    uint8_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
        }
        if (tmp_rc != tool_rc_success) {
            rc = tmp_rc;
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvextend", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
