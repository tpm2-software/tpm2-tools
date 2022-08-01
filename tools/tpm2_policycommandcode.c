/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2_cc_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policycommandcode_ctx tpm2_policycommandcode_ctx;
struct tpm2_policycommandcode_ctx {
    /*
     * Inputs
     */
    const char *session_path;
    TPM2_CC command_code;
    tpm2_session *session;

    /*
     * Outputs
     */
    const char *out_policy_dgst_path;
};

static tpm2_policycommandcode_ctx ctx;

static tool_rc tpm2_policycommandcode_build(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_policy_build_policycommandcode(ectx, ctx.session,
            ctx.command_code);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build TPM policy_command_code");
    }

    return rc;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.out_policy_dgst_path);
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
    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

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

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */

    return tool_rc_success;
}

static tool_rc check_options(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify only the TPM2 command code.");
        return false;
    }

    if (!argc) {
        LOG_ERR("TPM2 command code must be specified.");
        return false;
    }

    bool result = tpm2_cc_util_from_str(argv[0], &ctx.command_code);
    if (!result) {
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'S':
        ctx.session_path = value;
        break;
    case 'L':
        ctx.out_policy_dgst_path = value;
        break;
    }
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
    rc = tpm2_policycommandcode_build(ectx);
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

    /*
     * 2. Close authorization sessions
     */
    return tpm2_session_close(&ctx.session);

    /*
     * 3. Close auxiliary sessions
     */
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policycommandcode", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
