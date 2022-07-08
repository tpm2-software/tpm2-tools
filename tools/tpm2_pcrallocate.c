/* SPDX-License-Identifier: BSD-3-Clause */

#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

typedef struct tpm_pcrallocate_ctx tpm_pcrallocate_ctx;
struct tpm_pcrallocate_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    const char *user_pcr_alloc_str;
    TPML_PCR_SELECTION pcr_selection;

    /*
     * Outputs
     */
};

static tpm_pcrallocate_ctx ctx = {
    .auth_hierarchy.ctx_path = "platform",
    .pcr_selection = {
        .count = 2,
        .pcrSelections = { {
            .hash = TPM2_ALG_SHA1,
            .sizeofSelect = 3,
            .pcrSelect = { 0xff, 0xff, 0xff, }
            }, {
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 0xff, 0xff, 0xff, }
        }, }
    },
};

static tool_rc pcrallocate(ESYS_CONTEXT *ectx) {

    return tpm2_pcr_allocate(ectx, &ctx.auth_hierarchy.object,
        &ctx.pcr_selection);
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    pcr_print_pcr_selections(&ctx.pcr_selection);

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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid platform authorization format.");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * Use the default allocation defined in ctx initialization when pcr
     * allocation string is not specified.
     */
    if (ctx.user_pcr_alloc_str) {
        bool result = pcr_parse_selections(ctx.user_pcr_alloc_str,
            &ctx.pcr_selection);
        if (!result) {
            LOG_ERR("Could not parse pcr selections");
            return tool_rc_general_error;
        }
    }

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

static bool on_arg(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Too many arguments");
        return false;
    }

    if (argc == 1) {
        ctx.user_pcr_alloc_str = argv[0];
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
    const struct option topts[] = {
        { "auth", required_argument, NULL, 'P' }, 
    };

    *opts = tpm2_options_new("P:", ARRAY_LEN(topts), topts, on_option, on_arg,
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
    rc = pcrallocate(ectx);
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
    return tpm2_session_close(&ctx.auth_hierarchy.object.session);

    /*
     * 3. Close auxiliary sessions
     */

}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("pcrallocate", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
