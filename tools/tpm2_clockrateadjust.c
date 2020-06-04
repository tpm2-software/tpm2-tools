/* SPDX-License-Identifier: BSD-3-Clause */
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_setclock_ctx tpm2_setclock_ctx;
struct tpm2_setclock_ctx {
    TPM2_CLOCK_ADJUST adjust;
    const char *auth_hierarchy;
    tpm2_loaded_object object;
    const char *auth_value;
    char *cp_hash_path;
};

static tpm2_setclock_ctx ctx = {
        .auth_hierarchy = "o" /* default to owner hierarchy */
};

static bool on_arg(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Can only specify 1 clock rate adjust specifier, got: %d", argc);
        return false;
    }

    const char *adjustment = argv[0];

    size_t len = strlen(adjustment);
    if (len > 3) {
        LOG_ERR("Expected at most 3 adjustment characters");
        return false;
    }

    static const char slower[] = "sss";
    static const char faster[] = "fff";

    bool is_slower = adjustment[0] == 's';
    const char *compare = is_slower ? slower : faster;

    bool is_equal = !strncmp(adjustment, compare, len);
    if (!is_equal) {
        LOG_ERR("Adjustment specifier should be consistent, either all "
                "'s' or all 'f' characters got: \"%s\"", adjustment);
        return false;
    }

    if (is_slower) {
        ctx.adjust -= len;
    } else {
        ctx.adjust += len;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.auth_hierarchy = value;
        break;
    case 'p':
        ctx.auth_value = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy", required_argument, NULL, 'c' },
        { "auth",      required_argument, NULL, 'p' },
        { "cphash",    required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("c:p:", ARRAY_LEN(topts), topts, on_option,
    on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy,
            ctx.auth_value, &ctx.object, false,
            TPM2_HANDLE_FLAGS_P|TPM2_HANDLE_FLAGS_O);
    if (rc != tool_rc_success) {
        return rc;
    }

    LOG_INFO("adjust value: %d", ctx.adjust);

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        LOG_WARN("Calculating cpHash. Exiting without setting clock.");
        rc = tpm2_clockrateadjust(ectx, &ctx.object, ctx.adjust, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }
        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    return tpm2_clockrateadjust(ectx, &ctx.object, ctx.adjust, NULL);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("clockrateadjust", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
