/* SPDX-License-Identifier: BSD-3-Clause */
#include <string.h>

#include <log.h>
#include <tpm2.h>
#include "tpm2_tool.h"

#include "files.h"

typedef struct hierarchycontrol_ctx hierarchycontrol_ctx;
struct hierarchycontrol_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPMI_RH_ENABLES enable;
    TPMI_YES_NO state;

    char *cp_hash_path;
};

static hierarchycontrol_ctx ctx = {
    .auth_hierarchy.ctx_path = "p",
};

static tool_rc hierarchycontrol(ESYS_CONTEXT *ectx) {

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_hierarchycontrol(ectx, &ctx.auth_hierarchy.object,
        ctx.enable, ctx.state, &cp_hash);
        if (rc == tool_rc_success) {
            bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
            if (!result) {
                LOG_ERR("Failed to save cp hash");
                rc = tool_rc_general_error;
            }
        }
        return rc;
    }

    LOG_INFO ("Using hierarchy %s to \'%s\' TPMA_STARTUP_CLEAR bit (%s)",
        ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_OWNER ? "TPM2_RH_OWNER" :
        ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_ENDORSEMENT ? "TPM2_RH_ENDORSEMENT" :
        ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_PLATFORM ? "TPM2_RH_PLATFORM" : "TPM2_RH_PLATFORM_NV",
        ctx.enable == TPM2_RH_PLATFORM ? "phEnable" :
        ctx.enable == TPM2_RH_OWNER ? "shEnable" :
        ctx.enable == TPM2_RH_ENDORSEMENT ? "ehEnable" : "phEnableNV",
        ctx.state ? "SET" : "CLEAR");

    tool_rc rc = tpm2_hierarchycontrol(ectx, &ctx.auth_hierarchy.object,
        ctx.enable, ctx.state, NULL);

    if (rc != tool_rc_success) {
        LOG_ERR("Failed hierarchycontrol operation.");
    }

    return rc;
}

static bool on_arg(int argc, char **argv) {

    switch (argc) {
    case 2:
        break;
    default:
        return false;
    }

    if (!strcmp(argv[0], "phEnable")) {
        ctx.enable = TPM2_RH_PLATFORM;
    } else if (!strcmp(argv[0], "shEnable")) {
        ctx.enable = TPM2_RH_OWNER;
    } else if (!strcmp(argv[0], "ehEnable")) {
        ctx.enable = TPM2_RH_ENDORSEMENT;
    } else if (!strcmp(argv[0], "phEnableNV")) {
        ctx.enable = TPM2_RH_PLATFORM_NV;
    } else {
        LOG_ERR("Incorrect property, got: \"%s\", expected "
                "[phEnable|shEnable|ehEnable|phEnableNV]", argv[0]);
        return false;
    }

    if (!strcmp(argv[1], "set")) {
        ctx.state = TPM2_YES;
    } else if (!strcmp(argv[1], "clear")) {
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
        { "hierarchy",      required_argument, NULL, 'C' },
        { "hierarchy-auth", required_argument, NULL, 'P' },
        { "cphash",         required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:P:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

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
    } else {
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

    return hierarchycontrol(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("hierarchycontrol", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
