/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"

#define DEFAULT_ATTRS \
     TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
    |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
    |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH

#define DEFAULT_PRIMARY_KEY_ALG "rsa2048:null:aes128cfb"

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    struct {
        char *auth_str;
        tpm2_session *session;
    } parent;

    tpm2_hierarchy_pdata objdata;
    char *context_file;
    char *unique_file;
    char *key_auth_str;
    char *creation_data_file;
    char *creation_ticket_file;
    char *creation_hash_file;
    char *outside_info_data;
    char *template_data_path;

    char *alg;
    char *halg;
    char *attrs;
    char *policy;

    char *cp_hash_path;
};

static tpm_createprimary_ctx ctx = {
    .alg = DEFAULT_PRIMARY_KEY_ALG,
    .objdata = {
        .in = {
            .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
            .hierarchy = TPM2_RH_OWNER
        },
    },
};

static bool on_option(char key, char *value) {

    bool res;

    switch (key) {
    case 'C': {
        res = tpm2_util_handle_from_optarg(value, &ctx.objdata.in.hierarchy,
                TPM2_HANDLE_FLAGS_ALL_HIERACHIES);

        if (!res) {
            return false;
        }
        break;
    }
    case 'P':
        ctx.parent.auth_str = value;
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
        if (!pcr_parse_selections(value, &ctx.objdata.in.creation_pcr)) {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        break;
    case 2:
        ctx.cp_hash_path = value;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",      required_argument, NULL, 'C' },
        { "hierarchy-auth", required_argument, NULL, 'P' },
        { "key-auth",       required_argument, NULL, 'p' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "key-algorithm",  required_argument, NULL, 'G' },
        { "key-context",    required_argument, NULL, 'c' },
        { "policy",         required_argument, NULL, 'L' },
        { "attributes",     required_argument, NULL, 'a' },
        { "unique-data",    required_argument, NULL, 'u' },
        { "creation-data",  required_argument, NULL,  0  },
        { "template-data",  required_argument, NULL,  1  },
        { "creation-ticket",required_argument, NULL, 't' },
        { "creation-hash",  required_argument, NULL, 'd' },
        { "outside-info",   required_argument, NULL, 'q' },
        { "pcr-list",       required_argument, NULL, 'l' },
        { "cphash",         required_argument, NULL,  2  },
    };

    *opts = tpm2_options_new("C:P:p:g:G:c:L:a:u:t:d:q:l:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc validate_input_options(void) {

    if (ctx.cp_hash_path && (ctx.creation_data_file || ctx.creation_hash_file ||
    ctx.creation_ticket_file || ctx.context_file)) {
        LOG_ERR("Cannot generate outputs when calculating cpHash");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /* Parent/ Hierarchy Auth */
    tool_rc rc = tpm2_auth_util_from_optarg(ectx, ctx.parent.auth_str,
            &ctx.parent.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid parent key authorization");
        return rc;
    }

    /* Primary key auth */
    tpm2_session *tmp;
    rc = tpm2_auth_util_from_optarg(NULL, ctx.key_auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid new key authorization");
        return rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.objdata.in.sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

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
     * Template saved regardless of execution of the TPM2_CC_CreatePrimary.
     *
     * TODO: Does this need to be part of the no_execute_only_process_params
     *       along side processing cphash.
     *
     */
    if (ctx.template_data_path) {
        bool result = files_save_template(&ctx.objdata.in.public.publicArea,
            ctx.template_data_path);
        if (!result) {
            LOG_ERR("Could not save public template to file.");
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static tool_rc no_execute_only_process_params(ESYS_CONTEXT *ectx) {

    TPM2B_DIGEST cp_hash = { .size = 0 };
    tool_rc rc = tpm2_hierarchy_create_primary(ectx, ctx.parent.session,
    &ctx.objdata, &cp_hash);

    if (rc == tool_rc_success) {
        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            LOG_ERR("Failed to save cp hash");
            rc = tool_rc_general_error;
        }
    }

    return rc;
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    tpm2_util_public_to_yaml(ctx.objdata.out.public, NULL);

    tool_rc  rc = ctx.context_file ? files_save_tpm_context_to_path(ectx,
    ctx.objdata.out.handle, ctx.context_file) : tool_rc_success;
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

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /* Validate input options */
    tool_rc rc = validate_input_options();
    if (rc != tool_rc_success) {
        return tool_rc_option_error;
    }

    /* Process inputs */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Process & return uncoditionally if no execute paths are to be executed */
    if (ctx.cp_hash_path) { // One of the conditions for no execute
        return no_execute_only_process_params(ectx);
    }

    /* Dispatch TPM2_CC_CreatePrimary */
    rc = tpm2_hierarchy_create_primary(ectx, ctx.parent.session, &ctx.objdata,
    NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Process outputs and return */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.parent.session);
}

static void tpm2_tool_onexit(void) {

    tpm2_hierarchy_pdata_free(&ctx.objdata);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("createprimary", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, tpm2_tool_onexit)
