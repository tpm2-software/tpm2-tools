/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_convert.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

typedef struct tpm_create_ctx tpm_create_ctx;
#define MAX_AUX_SESSIONS 2
#define MAX_SESSIONS 3
struct tpm_create_ctx {
        /*
         * Inputs
         */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        char *sealed_data;
        char *auth_str;
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC in_public;
        TPM2B_DATA outside_info;
        TPML_PCR_SELECTION creation_pcr;
        char *outside_info_data;
        char *alg;
        char *attrs;
        char *name_alg;
        char *policy;
        bool is_object_alg_specified;
        bool is_sealing_input_specified;

        /*
         * Outputs
         */
        char *public_path;
        TPM2B_PUBLIC *out_public;
        const char *ctx_path;
        char *private_path;
        TPM2B_PRIVATE *out_private;
        char *creation_data_file;
        TPM2B_CREATION_DATA *creation_data;
        char *creation_hash_file;
        TPM2B_DIGEST *creation_hash;
        char *creation_ticket_file;
        TPMT_TK_CREATION *creation_ticket;
        char *template_data_path;
        ESYS_TR object_handle;
    } object;

    bool is_createloaded;
    bool autoflush;
    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    TPMI_ALG_HASH parameter_hash_algorithm;
    bool is_command_dispatch;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];

    /*
     * Formated public key output
     */
    char *output_path;
    bool format_set;
    tpm2_convert_pubkey_fmt format;
};

#define DEFAULT_KEY_ALG "rsa2048"

static tpm_create_ctx ctx = {
        .object = {
            .alg = DEFAULT_KEY_ALG,
            .creation_pcr = { .count = 0 },
            .object_handle = ESYS_TR_NONE,
            .outside_info.size = 0,
        },
        .aux_session_handle[0] = ESYS_TR_NONE,
        .aux_session_handle[1] = ESYS_TR_NONE,
        .cp_hash.size = 0,
        .is_command_dispatch = true,
        .parameter_hash_algorithm = TPM2_ALG_ERROR,
        .format = pubkey_format_tss,
        .autoflush = false,
};

static bool load_outside_info(TPM2B_DATA *outside_info) {

    outside_info->size = sizeof(outside_info->buffer);
    return tpm2_util_bin_from_hex_or_file(ctx.object.outside_info_data,
        &outside_info->size, outside_info->buffer);
}

static void print_help_message() {

    static const char *msg =
        "NOTE: The TPM does not support CreateLoaded command!\n"
        "Use tpm2_create with the -u and -r options and then\n"
        "call tpm2_load with -c and use the -u and -r outputs\n"
        "of tpm2_create in tpm2_load.";

    tpm2_tool_output("%s\n", msg);
}

static tool_rc create(ESYS_CONTEXT *ectx) {

    TSS2_RC rval;

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */

    /* TPM2_CC_CreateLoaded */
    if (ctx.is_createloaded) {
        size_t offset = 0;
        TPM2B_TEMPLATE template = { .size = 0 };
        tool_rc tmp_rc = tpm2_mu_tpmt_public_marshal(
                &ctx.object.in_public.publicArea, &template.buffer[0],
                sizeof(TPMT_PUBLIC), &offset);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }

        template.size = offset;

        tmp_rc = tpm2_create_loaded(ectx, &ctx.parent.object,
            &ctx.object.sensitive, &template, &ctx.object.object_handle,
            &ctx.object.out_private, &ctx.object.out_public, &ctx.cp_hash,
            &ctx.rp_hash, ctx.parameter_hash_algorithm,
            ctx.aux_session_handle[0], ctx.aux_session_handle[1]);
        if (tmp_rc != tool_rc_success) {
            if (tmp_rc == tool_rc_unsupported) {
                print_help_message();
            }
            return tmp_rc;
        }
    }

    /* TPM2_CC_Create */
    if (!ctx.is_createloaded) {
        /*
         * Outside data is optional. If not specified default to 0
         */
        bool result = ctx.object.outside_info_data ?
        load_outside_info(&ctx.object.outside_info) : true;
        if (!result) {
            return tool_rc_general_error;
        }

        tool_rc tmp_rc = tpm2_create(ectx, &ctx.parent.object,
            &ctx.object.sensitive, &ctx.object.in_public,
            &ctx.object.outside_info, &ctx.object.creation_pcr,
            &ctx.object.out_private, &ctx.object.out_public,
            &ctx.object.creation_data, &ctx.object.creation_hash,
            &ctx.object.creation_ticket, &ctx.cp_hash, &ctx.rp_hash,
            ctx.parameter_hash_algorithm, ctx.aux_session_handle[0],
            ctx.aux_session_handle[1]);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }
    }

    if ((ctx.autoflush || tpm2_util_env_yes(TPM2TOOLS_ENV_AUTOFLUSH)) &&
        ctx.parent.object.path &&
        (ctx.parent.object.handle & TPM2_HR_RANGE_MASK) == TPM2_HR_TRANSIENT) {
        rval = Esys_FlushContext(ectx, ctx.parent.object.tr_handle);
        if (rval != TPM2_RC_SUCCESS) {
            return tool_rc_general_error;
        }
    }
    return tool_rc_success;
}

static void setup_attributes(TPMA_OBJECT *attrs) {

    if (ctx.object.is_sealing_input_specified && !ctx.object.attrs) {
        *attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
        *attrs &= ~TPMA_OBJECT_DECRYPT;
        *attrs &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
    }

    if (!ctx.object.is_sealing_input_specified && !ctx.object.attrs &&
        !strncmp("hmac", ctx.object.alg, 4)) {
        *attrs &= ~TPMA_OBJECT_DECRYPT;
    }

    if (!ctx.object.attrs && ctx.object.policy && !ctx.object.auth_str) {
        *attrs &= ~TPMA_OBJECT_USERWITHAUTH;
    }
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.is_createloaded && ctx.object.template_data_path) {
        is_file_op_success = files_save_template(
            &ctx.object.in_public.publicArea, ctx.object.template_data_path);

        if (!is_file_op_success) {
            LOG_ERR("Could not save public template to file.");
            return tool_rc_general_error;
        }
    }

    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            LOG_ERR("Failed to save cp hash");
            return tool_rc_general_error;
        }
    }

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    /* TPM2_CC_Create outputs */
    tool_rc rc = tool_rc_success;
    if (!ctx.is_createloaded && ctx.object.creation_data_file &&
        ctx.object.creation_data->size) {
        is_file_op_success = files_save_creation_data(ctx.object.creation_data,
            ctx.object.creation_data_file);

        if (!is_file_op_success) {
            LOG_ERR("Failed saving creation data.");
            rc = tool_rc_general_error;
            goto create_out;
        }
    }

    if (!ctx.is_createloaded && ctx.object.creation_ticket_file &&
        ctx.object.creation_ticket->digest.size) {
        is_file_op_success = files_save_creation_ticket(
            ctx.object.creation_ticket, ctx.object.creation_ticket_file);

        if (!is_file_op_success) {
            LOG_ERR("Failed saving creation ticket.");
            rc = tool_rc_general_error;
            goto create_out;
        }
    }

    if (!ctx.is_createloaded && ctx.object.creation_hash_file &&
        ctx.object.creation_hash->size) {
        is_file_op_success = files_save_digest(ctx.object.creation_hash,
            ctx.object.creation_hash_file);

        if (!is_file_op_success) {
            LOG_ERR("Failed saving creation hash.");
            rc = tool_rc_general_error;
        }
    }

    if (ctx.output_path) {
        bool result = tpm2_convert_pubkey_save(ctx.object.out_public, ctx.format, ctx.output_path);
        if (!result) {
            LOG_ERR("Failed saving public key.");
            return tool_rc_general_error;
        }
    }

create_out:
    free(ctx.object.creation_data);
    free(ctx.object.creation_hash);
    free(ctx.object.creation_ticket);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Common- TPM2_CC_Create/ TPM2_CC_CreateLoaded outputs*/
    tpm2_util_public_to_yaml(ctx.object.out_public, NULL);

    if (ctx.object.public_path) {
        is_file_op_success = files_save_public(ctx.object.out_public,
            ctx.object.public_path);

        if (!is_file_op_success) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    if (ctx.object.private_path) {
        is_file_op_success = files_save_private(ctx.object.out_private,
            ctx.object.private_path);

        if (!is_file_op_success) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

    if (ctx.object.ctx_path) {
        rc = files_save_tpm_context_to_path(ectx, ctx.object.object_handle,
             ctx.object.ctx_path, ctx.autoflush);
        
        if (rc != tool_rc_success) {
            goto out;
        }
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);

        if (!is_file_op_success) {
            rc = tool_rc_general_error;
        }
    }

out:
    free(ctx.object.out_private);
    free(ctx.object.out_public);

    return rc;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */
    tpm2_session *tmp;
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, ctx.object.auth_str, &tmp,
        true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }
    TPM2B_AUTH const *auth = tpm2_session_get_auth_value(tmp);
    ctx.object.sensitive.sensitive.userAuth = *auth;
    tpm2_session_close(&tmp);

    /*
     * 1.b Add object names and their auth sessions
     */
    rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
        ctx.parent.auth_str, &ctx.parent.object, false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
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

    /* Setup attributes */
    TPMA_OBJECT attrs = DEFAULT_CREATE_ATTRS;
    setup_attributes(&attrs);

    /* Initialize object */
    rc = tpm2_alg_util_public_init(ctx.object.alg, ctx.object.name_alg,
        ctx.object.attrs, ctx.object.policy, attrs, &ctx.object.in_public);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Check object validitity */
    if (ctx.object.is_sealing_input_specified &&
        ctx.object.in_public.publicArea.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        return tool_rc_general_error;
    }

    /* Check command type */
    if ((ctx.object.ctx_path || ctx.object.template_data_path)) {
        ctx.is_createloaded = true;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.parent.object.session,
        ctx.aux_session[0],
        ctx.aux_session[1]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    return rc;
}

static tool_rc check_options(void) {

    if (!ctx.parent.ctx_path) {
        LOG_ERR("Must specify parent object via -C.");
        return tool_rc_option_error;
    }

    if (ctx.object.is_sealing_input_specified && ctx.object.is_object_alg_specified) {
        LOG_ERR("Cannot specify -G and -i together.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && !ctx.rp_hash_path &&
       (ctx.object.public_path || ctx.object.private_path ||
        ctx.object.creation_data_file || ctx.object.creation_hash_file ||
        ctx.object.creation_ticket_file || ctx.object.ctx_path)) {
        LOG_ERR("CpHash Error: Cannot specify pub, priv, creation - data, hash, ticket");
        return tool_rc_option_error;
    }

    if (ctx.format_set && !ctx.output_path) {
        LOG_ERR("Cannot specify --format/-f without specifying --output/-o");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool load_sensitive(void) {

    ctx.object.sensitive.sensitive.data.size = BUFFER_SIZE(
            typeof(ctx.object.sensitive.sensitive.data), buffer);

    return files_load_bytes_from_buffer_or_file_or_stdin(NULL,
        ctx.object.sealed_data, &ctx.object.sensitive.sensitive.data.size,
        ctx.object.sensitive.sensitive.data.buffer);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'p':
        ctx.object.auth_str = value;
        break;
    case 'g':
        ctx.object.name_alg = value;
        break;
    case 'G':
        ctx.object.alg = value;
        ctx.object.is_object_alg_specified = true;
        break;
    case 'a':
        ctx.object.attrs = value;
        break;
    case 'i':
        ctx.object.sealed_data = strcmp("-", value) ? value : NULL;
        ctx.object.alg = "keyedhash";
        ctx.object.is_sealing_input_specified = true;
        bool res = load_sensitive();
        if (!res) {
            return false;
        }
        break;
    case 'L':
        ctx.object.policy = value;
        break;
    case 'u':
        ctx.object.public_path = value;
        break;
    case 'r':
        ctx.object.private_path = value;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'c':
        ctx.object.ctx_path = value;
        break;
    case 0:
        ctx.object.creation_data_file = value;
        break;
    case 1:
        ctx.object.template_data_path = value;
        break;
    case 't':
        ctx.object.creation_ticket_file = value;
        break;
    case 'd':
        ctx.object.creation_hash_file = value;
        break;
    case 'q':
        ctx.object.outside_info_data = value;
        break;
    case 'l':
        if (!pcr_parse_selections(value, &ctx.object.creation_pcr, NULL)) {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        break;
    case 2:
        ctx.cp_hash_path = value;
        break;
    case 3:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            LOG_ERR("Specify a max of 3 sessions");
            return false;
        }
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
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "parent-auth",    required_argument, NULL, 'P' },
      { "key-auth",       required_argument, NULL, 'p' },
      { "hash-algorithm", required_argument, NULL, 'g' },
      { "key-algorithm",  required_argument, NULL, 'G' },
      { "attributes",     required_argument, NULL, 'a' },
      { "sealing-input",  required_argument, NULL, 'i' },
      { "policy",         required_argument, NULL, 'L' },
      { "public",         required_argument, NULL, 'u' },
      { "private",        required_argument, NULL, 'r' },
      { "parent-context", required_argument, NULL, 'C' },
      { "key-context",    required_argument, NULL, 'c' },
      { "creation-data",  required_argument, NULL,  0  },
      { "template-data",  required_argument, NULL,  1  },
      { "creation-ticket",required_argument, NULL, 't' },
      { "creation-hash",  required_argument, NULL, 'd' },
      { "outside-info",   required_argument, NULL, 'q' },
      { "pcr-list",       required_argument, NULL, 'l' },
      { "cphash",         required_argument, NULL,  2  },
      { "rphash",         required_argument, NULL,  3  },
      { "session",        required_argument, NULL, 'S' },
      { "format",         required_argument, NULL, 'f' },
      { "output",         required_argument, NULL, 'o' },
      { "autoflush",      no_argument,       NULL, 'R' },
    };

    *opts = tpm2_options_new("P:p:g:G:a:i:L:u:r:C:c:t:d:q:l:S:o:f:R",
    ARRAY_LEN(topts), topts, on_option, NULL, 0);

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
    rc = create(ectx);
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
    tool_rc tmp_rc = tpm2_session_close(&ctx.parent.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("create", tpm2_tool_onstart, tpm2_tool_onrun,
tpm2_tool_onstop, NULL)
