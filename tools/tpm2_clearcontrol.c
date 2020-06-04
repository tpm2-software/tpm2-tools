/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"

typedef struct clearcontrol_ctx clearcontrol_ctx;
struct clearcontrol_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPMI_YES_NO disable_clear;

    char *cp_hash_path;
};

static clearcontrol_ctx ctx = {
    .auth_hierarchy.ctx_path = "p",
    .disable_clear = 0,
};

static tool_rc clearcontrol(ESYS_CONTEXT *ectx) {

    LOG_INFO("Sending TPM2_ClearControl(%s) disableClear command with auth "
             "handle %s", ctx.disable_clear ? "SET" : "CLEAR",
             ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_PLATFORM ?
                "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_clearcontrol(ectx, &ctx.auth_hierarchy.object,
        ctx.disable_clear, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    return tpm2_clearcontrol(ectx, &ctx.auth_hierarchy.object,
    ctx.disable_clear, NULL);
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify single set/clear operation as s|c|0|1.");
        return false;
    }

    if (!argc) {
        LOG_ERR("Disable clear SET/CLEAR operation must be specified.");
        return false;
    }

    if (!strcmp(argv[0], "s")) {
        ctx.disable_clear = 1;
        return true;
    }

    if (!strcmp(argv[0], "c")) {
        ctx.disable_clear = 0;
        return true;
    }

    uint32_t value;
    bool result = tpm2_util_string_to_uint32(argv[0], &value);
    if (!result) {
        LOG_ERR("Please specify 0|1|s|c. Could not convert string, got: \"%s\"",
                argv[0]);
        return false;
    }

    if (value != 0 && value != 1) {
        LOG_ERR("Please use 0|1|s|c as the argument to specify operation");
        return false;
    }
    ctx.disable_clear = value;

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
        { "auth",           required_argument, NULL, 'P' },
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
            TPM2_HANDLE_FLAGS_P | TPM2_HANDLE_FLAGS_L);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid authorization");
        return rc;
    }

    if (!ctx.disable_clear
            && ctx.auth_hierarchy.object.tr_handle == ESYS_TR_RH_LOCKOUT) {
        LOG_ERR("Only platform hierarchy handle can be specified"
                " for CLEAR operation on disableClear");
        return tool_rc_general_error;
    }

    if (ctx.cp_hash_path) {
        LOG_WARN("Calculating cpHash. Exiting without configuring disableClear");
    }

    return clearcontrol(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("clearcontrol", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
