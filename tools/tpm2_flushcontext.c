/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_capability.h"
#include "tpm2_options.h"
#include "tpm2_session.h"

#define MAX_SESSIONS 3
#define TOTAL_CTX_TYPES 3 // contexts are transient/ loaded/ saved.
#define MAX_CTX_COUNT 255
struct tpm_flush_context_ctx {
    /*
     * Inputs
     */
    unsigned encountered_option_flags;
    TPM2_HANDLE property[TOTAL_CTX_TYPES];
    ESYS_TR context_handles[MAX_CTX_COUNT]; //ESYS_TR
    uint8_t context_handle_count;
    bool is_t_l_s_specified; //t l s option combination

    bool is_arg_session;
    bool is_arg_transient;
    char *context_arg;
    tpm2_session *arg_session;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;

};

static struct tpm_flush_context_ctx ctx = {
    .context_handles = {ESYS_TR_NONE},
    .parameter_hash_algorithm = TPM2_ALG_ERROR
};

static const char *get_property_name(TPM2_HANDLE handle) {

    switch (handle & TPM2_HR_RANGE_MASK) {
    case TPM2_HR_TRANSIENT:
        return "transient";
    case TPM2_HT_LOADED_SESSION << TPM2_HR_SHIFT:
        return "loaded session";
    case TPM2_HT_SAVED_SESSION << TPM2_HR_SHIFT:
        return "saved session";
    }

    return "invalid";
}

static tool_rc flushcontext(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tool_rc_success;
    uint32_t i;
    for (i = 0; i < ctx.context_handle_count; ++i) {
        /*
         * Continue flushing the handles after error AND
         * Capture the error as final return data.
         */
        tmp_rc = tpm2_flush_context(ectx, ctx.context_handles[i], &ctx.cp_hash,
            ctx.parameter_hash_algorithm);
        if (tmp_rc != tool_rc_success) {
            LOG_ERR("Failed Flush Context for %s handle 0x%x",
                get_property_name(ctx.context_handles[i]),
                ctx.context_handles[i]);
            rc = tmp_rc;
        }
    }

    return rc;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

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

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
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
    TPM2_HANDLE sapi_handle = 0;
    if (!ctx.is_t_l_s_specified) {
        ctx.is_arg_transient = tpm2_util_string_to_uint32(ctx.context_arg,
            &sapi_handle);
    }

    if (ctx.is_arg_transient) {
        rc = tpm2_util_sys_handle_to_esys_handle(ectx, sapi_handle,
            ctx.context_handles);
        if (rc != tool_rc_success) {
            LOG_ERR("Handle not found.");
            return rc;
        }

        ctx.context_handle_count++;
    }

    if (!ctx.is_t_l_s_specified && !ctx.is_arg_transient) {
        rc = tpm2_session_restore(ectx, ctx.context_arg, true,
            &ctx.arg_session);
        if (rc == tool_rc_success) {
            ctx.is_arg_session = true;
            ctx.context_handles[0] = tpm2_session_get_handle(ctx.arg_session);
            ctx.context_handle_count++;
        }
    }

    if (!ctx.is_t_l_s_specified && !ctx.is_arg_transient &&
    !ctx.is_arg_session) {
        LOG_ERR("Argument neither a session nor a transient.");
        return tool_rc_general_error;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * Populate ctx.context_handles with transient, loaded and saved handles
     * Note: encountered_option is nil when context is specified as argument.
     */
    TPM2_HANDLE property[3] = { 0 };
    unsigned offset = 0;
    if (ctx.encountered_option_flags & 1 << 0) {
        property[offset++] = TPM2_TRANSIENT_FIRST;
    }
    if (ctx.encountered_option_flags & 1 << 1) {
        property[offset++] = TPM2_LOADED_SESSION_FIRST;
    }
    if (ctx.encountered_option_flags & 1 << 2) {
        property[offset++] = TPM2_ACTIVE_SESSION_FIRST;
    }

    unsigned i = 0; // Iterates through t,l,s types
    for (i = 0; i < offset; i++) {
        TPM2_HANDLE p = property[i];
        TPMS_CAPABILITY_DATA *capability_data;
        rc = tpm2_capability_get(ectx, TPM2_CAP_HANDLES, p,
            TPM2_MAX_CAP_HANDLES, &capability_data);
        if (rc != tool_rc_success) {
            LOG_ERR("Error reading handle info from TPM.");
            return tool_rc_general_error;
        }

        unsigned j = 0; //Iterates through all available handles in t/l/s
        for (j = 0; j < capability_data->data.handles.count; j++) {
            rc = tpm2_util_sys_handle_to_esys_handle(ectx,
                capability_data->data.handles.handle[j],
                &ctx.context_handles[j]);
            if (rc != tool_rc_success) {
                LOG_ERR("Error reading handle info from TPM.");
                return tool_rc_general_error;
            }
            ctx.context_handle_count++;
        }

        free(capability_data);
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        0,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    /*
     * Note: pHash cannot be calculated if multiple sessions are found needing
     *       to be flushed. This is because pHash output needs to be written to
     *       a single file which must contain a single pHash.
     * 
     *       This implies if ctx.context_handle_count > 1 and pHash must be
     *       be calculated --> Error out.
     */

    return tool_rc_success;
}

static tool_rc check_options(void) {

    /*
     * Either an argument specifying the context to flush
     * OR
     * Option to flush all must be specified
     */
    ctx.is_t_l_s_specified = ctx.encountered_option_flags;
    if (!ctx.is_t_l_s_specified && !ctx.context_arg) {
        LOG_ERR("Specify options to evict handles or a session context.");
        return tool_rc_option_error;
    }

    /*
     * Options are mutually exclusive of an argument
     */
    if (ctx.is_t_l_s_specified && ctx.context_arg) {
        LOG_ERR("Specify either 't' 'l' 's' or a context. Cannot specify both");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc > 1) {
        LOG_ERR("Specify one context.");
        return tool_rc_option_error;
    }

    ctx.context_arg = argv[0];

    return true;
}

static bool on_option(char key, char *value) {

    UNUSED(value);

    switch (key) {
    case 't':
        ctx.encountered_option_flags |= 1 << 0;
        break;
    case 'l':
        ctx.encountered_option_flags |= 1 << 1;
        break;
    case 's':
        ctx.encountered_option_flags |= 1 << 2;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "transient-object", no_argument, 0, 't' },
        { "loaded-session",   no_argument, 0, 'l' },
        { "saved-session",    no_argument, 0, 's' },
        { "cphash",     required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("tls", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

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
    rc = flushcontext(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    if (ctx.is_arg_session) {
        tpm2_session_free(&ctx.arg_session);
    }

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("flushcontext", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
