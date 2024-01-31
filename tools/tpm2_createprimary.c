/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_convert.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"

#define MAX_SESSIONS 3
typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    tpm2_hierarchy_pdata objdata;
    char *alg;
    char *halg;
    char *attrs;
    char *policy;
    char *key_auth_str;
    char *unique_file;
    char *outside_info_data;
    bool autoflush;

    /*
     * Outputs
     */
    char *creation_data_file;
    char *creation_ticket_file;
    char *creation_hash_file;
    char *template_data_path;
    char *context_file;
    char *output_path;
    bool format_set;
    tpm2_convert_pubkey_fmt format;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

#define DEFAULT_PRIMARY_KEY_ALG "rsa2048:null:aes128cfb"
static tpm_createprimary_ctx ctx = {
    .alg = DEFAULT_PRIMARY_KEY_ALG,
    .objdata = {
        .in = {
            .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
            .hierarchy = TPM2_RH_OWNER
        },
    },
    .format = pubkey_format_tss,
    .auth_hierarchy.ctx_path = "owner",
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .autoflush = false,
};

static tool_rc createprimary(ESYS_CONTEXT *ectx) {

    return tpm2_create_primary(ectx, &ctx.auth_hierarchy.object,
        &ctx.objdata.in.sensitive, &ctx.objdata.in.public,
        &ctx.objdata.in.outside_info, &ctx.objdata.in.creation_pcr,
        &ctx.objdata.out.handle, &ctx.objdata.out.public,
        &ctx.objdata.out.creation.data, &ctx.objdata.out.hash,
        &ctx.objdata.out.creation.ticket, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {


    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    if (ctx.template_data_path) {
        bool result = files_save_template(&ctx.objdata.in.public.publicArea,
            ctx.template_data_path);
        if (!result) {
            LOG_ERR("Could not save public template to file.");
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    tpm2_util_public_to_yaml(ctx.objdata.out.public, 0);

    rc = ctx.context_file ? files_save_tpm_context_to_path(ectx,
         ctx.objdata.out.handle, ctx.context_file, ctx.autoflush) : tool_rc_success;
    if (rc != tool_rc_success) {
        LOG_ERR("Failed saving object context.");
        return rc;
    }

    bool result = true;
    if (ctx.creation_data_file) {
        result = files_save_creation_data(ctx.objdata.out.creation.data,
            ctx.creation_data_file);
    }
    if (!result) {
        LOG_ERR("Failed saving creation data.");
        return tool_rc_general_error;
    }

    if (ctx.creation_ticket_file) {
        result = files_save_creation_ticket(ctx.objdata.out.creation.ticket,
            ctx.creation_ticket_file);
    }
    if (!result) {
        LOG_ERR("Failed saving creation ticket.");
        return tool_rc_general_error;
    }

    if (ctx.creation_hash_file) {
        result = files_save_digest(ctx.objdata.out.hash,
            ctx.creation_hash_file);
    }
    if (!result) {
        LOG_ERR("Failed saving creation hash.");
        return tool_rc_general_error;
    }

    if (ctx.output_path) {
        result = tpm2_convert_pubkey_save(ctx.objdata.out.public, ctx.format, ctx.output_path);
        if (!result) {
            LOG_ERR("Failed saving public key.");
            return tool_rc_general_error;
        }
    }

    return rc;
}

#define DEFAULT_ATTRS \
     TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
    |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
    |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */
    /* Primary key auth */
    tpm2_session *tmp;
    tool_rc rc = tpm2_auth_util_from_optarg(0, ctx.key_auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid new key authorization");
        return rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.objdata.in.sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
        ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
        TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid hierarchy authorization");
        return rc;
    }
    ctx.objdata.in.hierarchy = ctx.auth_hierarchy.object.handle;

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    /*
     * Initialize the public properties of the key
     */
    rc = tpm2_alg_util_public_init(ctx.alg, ctx.halg, ctx.attrs,
            ctx.policy, DEFAULT_ATTRS, &ctx.objdata.in.public);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Optional unique data */
    if (ctx.unique_file) {
        if (!strcmp(ctx.unique_file, "-")) {
            ctx.unique_file = 0;
        }
        rc = files_load_unique_data(ctx.unique_file, &ctx.objdata.in.public);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    /* Outside data is optional. If not specified default to 0 */
    if (ctx.outside_info_data) {
        ctx.objdata.in.outside_info.size = sizeof(ctx.objdata.in.outside_info.buffer);
        bool result = tpm2_util_bin_from_hex_or_file(ctx.outside_info_data,
                &ctx.objdata.in.outside_info.size,
                ctx.objdata.in.outside_info.buffer);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);
    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    if (ctx.cp_hash_path && (ctx.creation_data_file || ctx.creation_hash_file ||
    ctx.creation_ticket_file || ctx.context_file)) {
        LOG_ERR("Cannot generate outputs when calculating cpHash");
        return tool_rc_option_error;
    }

    if (ctx.format_set && !ctx.output_path) {
        LOG_ERR("Cannot specify --format/-f without specifying --output/-o");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    bool result = true;
    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'p':
        ctx.key_auth_str = value;
        break;
    case 'g':
        ctx.halg = value;
        break;
    case 'G':
        ctx.alg = value;
        break;
    case 'c':
        ctx.context_file = value;
        break;
    case 'u':
        ctx.unique_file = value;
        break;
    case 'L':
        ctx.policy = value;
        break;
    case 'a':
        ctx.attrs = value;
        break;
    case 0:
        ctx.creation_data_file = value;
        break;
    case 1:
        ctx.template_data_path = value;
        break;
    case 't':
        ctx.creation_ticket_file = value;
        break;
    case 'd':
        ctx.creation_hash_file = value;
        break;
    case 'q':
        ctx.outside_info_data = value;
        break;
    case 'l':
        result = pcr_parse_selections(value, &ctx.objdata.in.creation_pcr,
                                      NULL);
        if (!result) {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return result;
        }
        break;
    case 2:
        ctx.cp_hash_path = value;
        break;
    case 'f':
        ctx.format = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.format_set = true;
        break;
    case 'o':
        ctx.output_path = value;
        break;
    case 'R':
        ctx.autoflush = true;
        break;
        /* no default */
    }

    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",      required_argument, 0, 'C' },
        { "hierarchy-auth", required_argument, 0, 'P' },
        { "key-auth",       required_argument, 0, 'p' },
        { "hash-algorithm", required_argument, 0, 'g' },
        { "key-algorithm",  required_argument, 0, 'G' },
        { "key-context",    required_argument, 0, 'c' },
        { "policy",         required_argument, 0, 'L' },
        { "attributes",     required_argument, 0, 'a' },
        { "unique-data",    required_argument, 0, 'u' },
        { "creation-data",  required_argument, 0,  0  },
        { "template-data",  required_argument, 0,  1  },
        { "creation-ticket",required_argument, 0, 't' },
        { "creation-hash",  required_argument, 0, 'd' },
        { "outside-info",   required_argument, 0, 'q' },
        { "pcr-list",       required_argument, 0, 'l' },
        { "cphash",         required_argument, 0,  2  },
        { "format",         required_argument, 0, 'f' },
        { "output",         required_argument, 0, 'o' },
        { "autoflush",      no_argument,       0, 'R' },
    };

    *opts = tpm2_options_new("C:P:p:g:G:c:L:a:u:t:d:q:l:o:f:R", ARRAY_LEN(topts),
        topts, on_option, 0, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
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
    rc = createprimary(ectx);
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
    tool_rc rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

static void tpm2_tool_onexit(void) {

    tpm2_hierarchy_pdata_free(&ctx.objdata);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("createprimary", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, tpm2_tool_onexit)
