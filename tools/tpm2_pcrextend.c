/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_auth_util.h"

typedef struct tpm_pcr_extend_ctx tpm_pcr_extend_ctx;
#define MAX_AUX_SESSIONS 2
#define MAX_SESSIONS 3
struct tpm_pcr_extend_ctx {
    /*
     * Inputs
     */
    struct {
        const char *auth_str;
        tpm2_session *session;
    } auth;

    size_t digest_spec_len;
    tpm2_pcr_digest_spec *digest_spec;

    /*
     * Outputs
     */

    /*
     * Aux Sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_pcr_extend_ctx ctx;

static tpm_pcr_extend_ctx ctx = {
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
};

static tool_rc pcr_extend(ESYS_CONTEXT *ectx,
                          ESYS_TR session_handle_2,
                          ESYS_TR session_handle_3) {

    size_t i;
    for (i = 0; i < ctx.digest_spec_len; i++) {
        tpm2_pcr_digest_spec *dspec = &ctx.digest_spec[i];
        tool_rc rc = tpm2_pcr_extend(ectx, dspec->pcr_index, ctx.auth.session,
                                     &dspec->digests,
                                     session_handle_2, session_handle_3);
        if (rc != tool_rc_success) {
            LOG_ERR("Could not extend pcr index: 0x%X", dspec->pcr_index);
            return rc;
        }
    }

    return tool_rc_success;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */

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
    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.auth.auth_str,
            &ctx.auth.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key handle authorization");
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

    return tool_rc_success;
}

static bool on_options(char key, char *value) {

    UNUSED(key);

    switch (key) {
    case 'P':
        ctx.auth.auth_str = value;
        break;
        /* no default */
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
        break;
        /* no default */
    }

    return true;
}


static bool on_arg(int argc, char **argv) {

    if (argc < 1) {
        LOG_ERR("Expected at least one PCR Digest specification,"
                "ie: <pcr index>:<hash alg>=<hash value>, got: 0");
        return false;
    }

    /* this can never be negative */
    ctx.digest_spec_len = (size_t) argc;

    ctx.digest_spec = calloc(ctx.digest_spec_len, sizeof(*ctx.digest_spec));
    if (!ctx.digest_spec) {
        LOG_ERR("oom");
        return false;
    }

    return pcr_parse_digest_list(argv, ctx.digest_spec_len, ctx.digest_spec);
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth",         required_argument, NULL, 'P' },
        { "session",      required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("P:S:", ARRAY_LEN(topts), topts, on_options, on_arg, 0);

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
    rc = pcr_extend(ectx,
                    ctx.aux_session_handle[0],
                    ctx.aux_session_handle[1]);
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

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

static void tpm2_tool_onexit(void) {

    free(ctx.digest_spec);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrextend", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, tpm2_tool_onexit)
