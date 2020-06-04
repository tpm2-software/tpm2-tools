/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policytemplate_ctx tpm2_policytemplate_ctx;
struct tpm2_policytemplate_ctx {
    //Input
    TPM2B_DIGEST template_hash;

    //Input/Output
    const char *session_file_path;
    tpm2_session *session;

    //Output
    const char *policy_digest_file_path;
};

static tpm2_policytemplate_ctx ctx;

static bool process_input_template_hash(char *value) {

    ctx.template_hash.size = sizeof(ctx.template_hash.buffer);
    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL, value,
            &ctx.template_hash.size, ctx.template_hash.buffer);
    if (!result) {
        LOG_ERR("Failed loading name hash from file");
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'L':
        ctx.policy_digest_file_path = value;
        break;
    case 'S':
        ctx.session_file_path = value;
        break;
    case 0:
        result = process_input_template_hash(value);
        break;
    }

    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",        required_argument, NULL, 'L' },
        { "session",       required_argument, NULL, 'S' },
        { "template-hash", required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("L:S:", ARRAY_LEN(topts), topts, on_option, NULL,
        0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.session_file_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.template_hash.size) {
        LOG_WARN("Template-hash file is of size zero");
    }

    return true;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_session_restore(ectx, ctx.session_file_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_policy_build_policytemplate(ectx, ctx.session, &ctx.template_hash);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policytemplate TPM");
        return rc;
    }

    return tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_file_path);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policytemplate", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
