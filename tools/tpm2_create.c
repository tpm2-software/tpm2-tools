/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

#define DEFAULT_ATTRS \
     TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM \
    |TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN \
    |TPMA_OBJECT_USERWITHAUTH

typedef struct tpm_create_ctx tpm_create_ctx;
struct tpm_create_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC public;
        char *sealed_data;
        char *public_path;
        char *private_path;
        char *auth_str;
        const char *ctx_path;
        char *creation_data_file;
        char *creation_ticket_file;
        char *creation_hash_file;
        char *template_data_path;
        char *alg;
        char *attrs;
        char *name_alg;
        char *policy;
    } object;

    char *outside_info_data;

    TPML_PCR_SELECTION creation_pcr;

    struct {
        UINT8 a :1;
        UINT8 i :1;
        UINT8 L :1;
        UINT8 u :1;
        UINT8 r :1;
        UINT8 G :1;
    } flags;

    char *cp_hash_path;
};

#define DEFAULT_KEY_ALG "rsa2048"

static tpm_create_ctx ctx = {
        .object = { .alg = DEFAULT_KEY_ALG },
        .creation_pcr = { .count = 0 },
};

static bool load_outside_info(TPM2B_DATA *outside_info) {

    outside_info->size = sizeof(outside_info->buffer);
    return tpm2_util_bin_from_hex_or_file(ctx.outside_info_data,
            &outside_info->size,
            outside_info->buffer);
}

static tool_rc create(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_general_error;

    TPM2B_PUBLIC *out_public;
    TPM2B_PRIVATE *out_private;

    ESYS_TR object_handle = ESYS_TR_NONE;
    TPM2B_DIGEST cp_hash = { .size = 0 };
    if (ctx.object.ctx_path &&
        (!ctx.object.creation_data_file &&
         !ctx.object.creation_ticket_file &&
         !ctx.object.creation_hash_file)
       ) {

        size_t offset = 0;
        TPM2B_TEMPLATE template = { .size = 0 };
        tool_rc tmp_rc = tpm2_mu_tpmt_public_marshal(
                &ctx.object.public.publicArea, &template.buffer[0],
                sizeof(TPMT_PUBLIC), &offset);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }

        template.size = offset;

        if (ctx.cp_hash_path) {
            tmp_rc = tpm2_create_loaded(ectx, &ctx.parent.object,
                &ctx.object.sensitive, &template, &object_handle, &out_private,
                &out_public, &cp_hash);
            if (tmp_rc == tool_rc_success) {
                bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
                if (!result) {
                    LOG_ERR("Failed to save cp hash");
                    tmp_rc = tool_rc_general_error;
                }
            }
            return tmp_rc;
        }

        tmp_rc = tpm2_create_loaded(ectx, &ctx.parent.object,
                &ctx.object.sensitive, &template, &object_handle, &out_private,
                &out_public, NULL);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }
    } else {
        /*
         * Outside data is optional. If not specified default to 0
         */
        bool result = true;
        TPM2B_DATA outside_info = TPM2B_EMPTY_INIT;
        if (ctx.outside_info_data) {
            result = load_outside_info(&outside_info);
        }
        if (!result) {
            return tool_rc_general_error;
        }

        tool_rc tmp_rc = tool_rc_success;
        if (ctx.cp_hash_path) {
            tmp_rc = tpm2_create(ectx, &ctx.parent.object,
                &ctx.object.sensitive, &ctx.object.public, &outside_info,
                &ctx.creation_pcr, &out_private, &out_public, NULL, NULL, NULL,
                &cp_hash);
            if (tmp_rc == tool_rc_success) {
                result = files_save_digest(&cp_hash, ctx.cp_hash_path);
                if (!result) {
                    LOG_ERR("Failed to save cp hash");
                    tmp_rc = tool_rc_general_error;
                }
            }
            return tmp_rc;
        }
        TPM2B_CREATION_DATA *creation_data = NULL;
        TPM2B_DIGEST *creation_hash = NULL;
        TPMT_TK_CREATION *creation_ticket = NULL;
        tmp_rc = tpm2_create(ectx, &ctx.parent.object,
                &ctx.object.sensitive, &ctx.object.public, &outside_info,
                &ctx.creation_pcr, &out_private, &out_public, &creation_data,
                &creation_hash, &creation_ticket, NULL);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }

        if (ctx.object.creation_data_file && creation_data->size) {
            result = files_save_creation_data(creation_data,
                ctx.object.creation_data_file);
        }
        if (!result) {
            LOG_ERR("Failed saving creation data.");
            tmp_rc = tool_rc_general_error;
            goto create_out;
        }

        if (ctx.object.creation_ticket_file && creation_ticket->digest.size) {
            result = files_save_creation_ticket(creation_ticket,
                ctx.object.creation_ticket_file);
        }
        if (!result) {
            LOG_ERR("Failed saving creation ticket.");
            tmp_rc = tool_rc_general_error;
            goto create_out;
        }

        if (ctx.object.creation_hash_file && creation_hash->size) {
            result = files_save_digest(creation_hash,
                ctx.object.creation_hash_file);
        }
        if (!result) {
            LOG_ERR("Failed saving creation hash.");
            tmp_rc = tool_rc_general_error;
            goto create_out;
        }

create_out:
        free(creation_data);
        free(creation_hash);
        free(creation_ticket);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }
    }

    if (ctx.object.template_data_path) {
        bool res = files_save_template(&ctx.object.public.publicArea,
        ctx.object.template_data_path);

        if (!res) {
            LOG_ERR("Could not save public template to file.");
            rc = tool_rc_general_error;
            goto out;
        }
    }

    tpm2_util_public_to_yaml(out_public, NULL);

    if (ctx.flags.u) {
        bool res = files_save_public(out_public, ctx.object.public_path);
        if (!res) {
            goto out;
        }
    }

    if (ctx.flags.r) {
        bool res = files_save_private(out_private, ctx.object.private_path);
        if (!res) {
            goto out;
        }
    }

    if (ctx.object.ctx_path) {
        rc = files_save_tpm_context_to_path(ectx, object_handle,
                ctx.object.ctx_path);
    } else {
        rc = tool_rc_success;
    }

out:
    free(out_private);
    free(out_public);

    return rc;
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
        ctx.flags.G = 1;
        break;
    case 'a':
        ctx.object.attrs = value;
        ctx.flags.a = 1;
        break;
    case 'i':
        ctx.object.sealed_data = strcmp("-", value) ? value : NULL;
        ctx.flags.i = 1;
        break;
    case 'L':
        ctx.object.policy = value;
        ctx.flags.L = 1;
        break;
    case 'u':
        ctx.object.public_path = value;
        ctx.flags.u = 1;
        break;
    case 'r':
        ctx.object.private_path = value;
        ctx.flags.r = 1;
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
        ctx.outside_info_data = value;
        break;
    case 'l':
        if (!pcr_parse_selections(value, &ctx.creation_pcr)) {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        break;
    case 2:
        ctx.cp_hash_path = value;
        break;
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
    };

    *opts = tpm2_options_new("P:p:g:G:a:i:L:u:r:C:c:t:d:q:l:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static bool load_sensitive(void) {

    ctx.object.sensitive.sensitive.data.size = BUFFER_SIZE(
            typeof(ctx.object.sensitive.sensitive.data), buffer);
    return files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.object.sealed_data, &ctx.object.sensitive.sensitive.data.size,
            ctx.object.sensitive.sensitive.data.buffer);
}

static tool_rc check_options(void) {

    if (!ctx.parent.ctx_path) {
        LOG_ERR("Must specify parent object via -C.");
        return tool_rc_option_error;
    }

    if (ctx.flags.i && ctx.flags.G) {
        LOG_ERR("Cannot specify -G and -i together.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && (ctx.object.public_path || ctx.object.private_path
        || ctx.object.creation_data_file || ctx.object.creation_hash_file ||
        ctx.object.creation_ticket_file || ctx.object.ctx_path)) {
        LOG_ERR("CpHash Error: Cannot specify pub, priv, creation - data, hash, ticket");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMA_OBJECT attrs = DEFAULT_ATTRS;

    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.flags.i) {

        bool res = load_sensitive();
        if (!res) {
            return tool_rc_general_error;
        }

        ctx.object.alg = "keyedhash";

        if (!ctx.flags.a) {
            attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
            attrs &= ~TPMA_OBJECT_DECRYPT;
            attrs &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
        }
    } else if (!ctx.flags.a && !strncmp("hmac", ctx.object.alg, 4)) {
        attrs &= ~TPMA_OBJECT_DECRYPT;
    }

    rc = tpm2_alg_util_public_init(ctx.object.alg, ctx.object.name_alg,
            ctx.object.attrs, ctx.object.policy, attrs, &ctx.object.public);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (!ctx.flags.a && ctx.flags.L && !ctx.object.auth_str) {
        ctx.object.public.publicArea.objectAttributes &=
                ~TPMA_OBJECT_USERWITHAUTH;
    }

    if (ctx.flags.i
            && ctx.object.public.publicArea.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        return tool_rc_general_error;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_session *tmp;
    rc = tpm2_auth_util_from_optarg(NULL, ctx.object.auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    TPM2B_AUTH const *auth = tpm2_session_get_auth_value(tmp);
    ctx.object.sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    return create(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.parent.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("create", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
