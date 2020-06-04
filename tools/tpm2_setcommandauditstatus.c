/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_cc_util.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_setcommandauditstatus_ctx tpm2_setcommandauditstatus_ctx;
struct tpm2_setcommandauditstatus_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } hierarchy;
    TPML_CC command_code_list;
    TPMI_ALG_HASH hash_algorithm;
    bool clear_list;
};

static tpm2_setcommandauditstatus_ctx ctx = {
    .hierarchy = {
        .ctx_path = "o",
    },
    .hash_algorithm = TPM2_ALG_SHA256,
    .clear_list = false
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.hierarchy.auth_str = value;
        break;
    case 'c':
        ctx.clear_list = true;
        break;
    case 'g':
        ctx.hash_algorithm = tpm2_alg_util_from_optarg(value,
        tpm2_alg_util_flags_hash);
        if (ctx.hash_algorithm == TPM2_ALG_ERROR) {
            return false;
        }
        break;
    default:
        LOG_ERR("Unknown option");
        return false;
    }
    return true;
}

static bool on_arg(int argc, char **argv) {

    if (argc > 1 || !argc) {
        LOG_ERR("Specify a TPM2 command to add/ remove from audit list.");
        return false;
    }

    if (ctx.command_code_list.count > TPM2_MAX_CAP_CC) {
        LOG_ERR("List of commands exceeds maximum supported command count");
        return false;
    }

    bool result = tpm2_cc_util_from_str(argv[0],
    &ctx.command_code_list.commandCodes[ctx.command_code_list.count]);
    if (!result) {
        return false;
    }
    ctx.command_code_list.count+=1;

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "hierarchy",      required_argument, NULL, 'C' },
        { "hierarchy-auth", required_argument, NULL, 'P' },
        { "clear-list",     no_argument,       NULL, 'c' },
        { "hash-algorithm", required_argument, NULL, 'g' },
    };

    *opts = tpm2_options_new("C:P:g:c", ARRAY_LEN(topts), topts, on_option,
     on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.hierarchy.ctx_path,
    ctx.hierarchy.auth_str , &ctx.hierarchy.object, false,
    TPM2_HANDLE_FLAGS_O|TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPML_CC empty_list = { 0 };
    /*
     * TPM does not allow to set commandaudit digest and commands to audit
     * simultaneously. So first set the command audit digest.
     */
    rc = tpm2_setcommandcodeaudit(ectx, &ctx.hierarchy.object, ctx.hash_algorithm,
    &empty_list, &empty_list);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to set command audit digest.");
        return rc;
    }

    rc = ctx.clear_list ?
    tpm2_setcommandcodeaudit(ectx, &ctx.hierarchy.object, ctx.hash_algorithm,
    &empty_list, &ctx.command_code_list) :
    tpm2_setcommandcodeaudit(ectx, &ctx.hierarchy.object, ctx.hash_algorithm,
    &ctx.command_code_list, &empty_list);

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("setcommandauditstatus", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
