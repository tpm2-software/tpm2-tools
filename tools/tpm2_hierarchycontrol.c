/* SPDX-License-Identifier: BSD-3-Clause */
#include <string.h>

#include <log.h>
#include <tpm2.h>
#include "tpm2_tool.h"

#include "files.h"

typedef struct hierarchycontrol_ctx hierarchycontrol_ctx;
#define MAX_SESSIONS 3
struct hierarchycontrol_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPMI_RH_ENABLES enable;
    TPMI_YES_NO state;

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

static hierarchycontrol_ctx ctx = {
    .auth_hierarchy.ctx_path = "p",
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc hierarchycontrol(ESYS_CONTEXT *ectx) {

    LOG_INFO ("Using hierarchy %s to \'%s\' TPMA_STARTUP_CLEAR bit (%s)",
        ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_OWNER ?
            "TPM2_RH_OWNER" :
        ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_ENDORSEMENT ?
            "TPM2_RH_ENDORSEMENT" :
        ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_PLATFORM ?
            "TPM2_RH_PLATFORM" : "TPM2_RH_PLATFORM_NV",
        ctx.enable == TPM2_RH_PLATFORM ? "phEnable" :
        ctx.enable == TPM2_RH_OWNER ? "shEnable" :
        ctx.enable == TPM2_RH_ENDORSEMENT ? "ehEnable" : "phEnableNV",
        ctx.state ? "SET" : "CLEAR");

    tool_rc rc = tpm2_hierarchycontrol(ectx, &ctx.auth_hierarchy.object,
        ctx.enable, ctx.state, &ctx.cp_hash, ctx.parameter_hash_algorithm);

    if (rc != tool_rc_success) {
        LOG_ERR("Failed hierarchycontrol operation.");
    }

    return rc;
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

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

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
    /*
     * auth_hierarchy already loaded in check_options
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
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

    return tool_rc_success;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_P | TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_E);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid authorization");
        return rc;
    }

    if (ctx.state == TPM2_YES) {
        switch (ctx.enable) {
        case TPM2_RH_PLATFORM:
            LOG_ERR("phEnable may not be SET using this command");
            return tool_rc_tcti_error;
        case TPM2_RH_OWNER:
        case TPM2_RH_ENDORSEMENT:
        case TPM2_RH_PLATFORM_NV:
            if (ctx.auth_hierarchy.object.tr_handle != ESYS_TR_RH_PLATFORM) {
                LOG_ERR("Only platform hierarchy handle can be specified for "
                        "SET \'%s\' bit",
                        ctx.enable == TPM2_RH_OWNER ? "shEnable" :
                        ctx.enable == TPM2_RH_ENDORSEMENT ? "ehEnable" :
                        ctx.enable == TPM2_RH_PLATFORM_NV ?
                                "phEnableNV" : "NONE");
                return tool_rc_auth_error;
            }
            break;
        default:
            LOG_ERR("Unknown permanent handle, got: \"0x%x\"", ctx.enable);
            return tool_rc_unsupported;
        }
    }

    if (ctx.state != TPM2_YES) {
        switch (ctx.enable) {
        case TPM2_RH_PLATFORM:
            if (ctx.auth_hierarchy.object.tr_handle != ESYS_TR_RH_PLATFORM) {
                LOG_ERR("Only platform hierarchy handle can be specified for "
                        "CLEAR \'phEnable\' bit");
                return tool_rc_general_error;
            }
            break;
        case TPM2_RH_OWNER:
            if (ctx.auth_hierarchy.object.tr_handle != ESYS_TR_RH_OWNER
                    && ctx.auth_hierarchy.object.tr_handle
                            != ESYS_TR_RH_PLATFORM) {
                LOG_ERR("Only platform and owner hierarchy handle can be "
                        "specified for CLEAR \'shEnable\' bit");
                return tool_rc_auth_error;
            }
            break;
        case TPM2_RH_ENDORSEMENT:
            if (ctx.auth_hierarchy.object.tr_handle != ESYS_TR_RH_ENDORSEMENT
                    && ctx.auth_hierarchy.object.tr_handle
                            != ESYS_TR_RH_PLATFORM) {
                LOG_ERR(
                        "Only platform and endorsement hierarchy handle can be "
                        "specified for CLEAR \'ehEnable\' bit");
                return tool_rc_auth_error;
            }
            break;
        case TPM2_RH_PLATFORM_NV:
            if (ctx.auth_hierarchy.object.tr_handle != ESYS_TR_RH_PLATFORM_NV
                    && ctx.auth_hierarchy.object.tr_handle
                            != ESYS_TR_RH_PLATFORM) {
                LOG_ERR(
                        "Only platform hierarchy handle can be specified for "
                        "CLEAR \'phEnableNV\' bit");
                return tool_rc_auth_error;
            }
            break;
        default:
            LOG_ERR("Unknown permanent handle, got: \"0x%x\"", ctx.enable);
            return tool_rc_unsupported;
        }
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    switch (argc) {
    case 2:
        break;
    default:
        return false;
    }

    bool is_phenable = strcmp(argv[0], "phEnable") == 0;
    bool is_shenable = strcmp(argv[0], "shEnable") == 0;
    bool is_ehenable = strcmp(argv[0], "ehEnable") == 0;
    bool is_phenablenv = strcmp(argv[0], "phEnableNV") == 0;
    if (is_phenable) {
        ctx.enable = TPM2_RH_PLATFORM;
    } else if (is_shenable) {
        ctx.enable = TPM2_RH_OWNER;
    } else if (is_ehenable) {
        ctx.enable = TPM2_RH_ENDORSEMENT;
    } else if (is_phenablenv) {
        ctx.enable = TPM2_RH_PLATFORM_NV;
    } else {
        LOG_ERR("Incorrect property, got: \"%s\", expected "
                "[phEnable|shEnable|ehEnable|phEnableNV]", argv[0]);
        return false;
    }

    bool is_set = strcmp(argv[1], "set") == 0;
    bool is_clear = strcmp(argv[1], "clear") == 0;
    if (is_set) {
        ctx.state = TPM2_YES;
    } else if (is_clear) {
        ctx.state = TPM2_NO;
    } else {
        LOG_ERR("Incorrect operation, got: \"%s\", expected [set|clear].",
            argv[1]);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",      required_argument, 0, 'C' },
        { "hierarchy-auth", required_argument, 0, 'P' },
        { "cphash",         required_argument, 0,  0  },
    };

    *opts = tpm2_options_new("C:P:", ARRAY_LEN(topts), topts, on_option, on_arg,
        0);

    return *opts != 0;
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
    rc = hierarchycontrol(ectx);
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
    tool_rc rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("hierarchycontrol", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
