/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_cc_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policynvwritten_ctx tpm2_policynvwritten_ctx;
struct tpm2_policynvwritten_ctx {
    const char *session_path;
    const char *policy_digest_path;
    tpm2_session *session;
    TPMI_YES_NO written_set;
};

static tpm2_policynvwritten_ctx ctx = {
    .written_set = TPM2_NO,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'S':
        ctx.session_path = value;
        break;
    case 'L':
        ctx.policy_digest_path = value;
        break;
    }
    return true;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify single NV written SET/CLEAR operation as s|c|0|1.");
        return false;
    }

    if (!argc) {
        LOG_ERR("Disable NV written SET/CLEAR operation must be specified.");
        return false;
    }

    if (!strcmp(argv[0], "s")) {
        ctx.written_set = TPM2_YES;
        return true;
    }

    if (!strcmp(argv[0], "c")) {
        ctx.written_set = TPM2_NO;
        return true;
    }

    uint32_t value;
    bool result = tpm2_util_string_to_uint32(argv[0], &value);
    if (!result) {
        LOG_ERR("Please specify 0|1|s|c. Could not convert string, got: \"%s\"",
                argv[0]);
        return false;
    }

    if (value != TPM2_NO && value != TPM2_YES) {
        LOG_ERR("Please use 0|1|s|c as the argument to specify operation");
        return false;
    }
    ctx.written_set = value;

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "session", required_argument,  NULL,   'S' },
        { "policy",  required_argument,  NULL,   'L' },
    };

    *opts = tpm2_options_new("S:L:", ARRAY_LEN(topts), topts, on_option, on_arg,
            0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_policynvwritten(ectx, ctx.session, ctx.written_set);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policy_nv_written!");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policynvwritten", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
