/* SPDX-License-Identifier: BSD-3-Clause */
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct tpm_pcr_setauthvalue_ctx tpm_pcr_setauthvalue_ctx;
#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2
struct tpm_pcr_setauthvalue_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } pcrindex_auth;

    char *pcrindex_auth_str;
    TPM2B_AUTH pcrindex_newauth;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */

    /*
     * Aux sessions
     */
};

static tpm_pcr_setauthvalue_ctx ctx = { 0 };

static tool_rc pcr_set_authvalue(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_pcr_setauthvalue(ectx, &ctx.pcrindex_auth.object,
        &ctx.pcrindex_newauth);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to set pcr authvalue");
    }

    return rc;
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

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

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */
    tpm2_session *tmp;
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, ctx.pcrindex_auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Error: cannot parse the pcrindex authvalue to be set");
        return rc;
    }
    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.pcrindex_newauth = *auth;
    tpm2_session_close(&tmp);

    /*
     * 1.b Add object names and their auth sessions
     */
    rc = tpm2_util_object_load_auth(ectx, ctx.pcrindex_auth.ctx_path,
        ctx.pcrindex_auth.auth_str, &ctx.pcrindex_auth.object, true,
        TPM2_HANDLE_FLAGS_PCR);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid PCR Index or authorization.");
        return tool_rc_option_error;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations dependent on loaded objects
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /* 4.a Determine pHash length and alg */

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * is_tcti_none       [N]
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */

    return rc;
}

static tool_rc check_options(tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.pcrindex_auth.ctx_path) {
        LOG_ERR("PCR Index must be specified as argument.");
        return tool_rc_option_error;
    }

    if (!ctx.pcrindex_auth_str) {
        LOG_ERR("Authvalue to be set for PCR index must be specified.");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.pcrindex_auth.auth_str = value;
        break;
    case 'p':
        ctx.pcrindex_auth_str = value;
        break;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    UNUSED(argc);

    if (!argv) {
        LOG_ERR("PCR Index must be specified");
        return false;
    }

    ctx.pcrindex_auth.ctx_path = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth",        required_argument, NULL, 'P' },
        { "newauth",     required_argument, NULL, 'p' },
    };

    *opts = tpm2_options_new("P:p:", ARRAY_LEN(topts), topts, on_option,
        on_arg, 0);

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
    rc = pcr_set_authvalue(ectx);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.pcrindex_auth.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrsetauthvalue", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
