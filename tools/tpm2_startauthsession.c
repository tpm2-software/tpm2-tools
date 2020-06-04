/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

#include "log.h"
#include "object.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm2_startauthsession_ctx tpm2_startauthsession_ctx;
struct tpm2_startauthsession_ctx {
    struct {
        TPM2_SE type;
        TPMI_ALG_HASH halg;
        const char *key_context_arg_str;
        tpm2_loaded_object key_context_object;
    } session;
    struct {
        const char *path;
    } output;

    tpm2_session_data *session_data;
    TPMA_SESSION attrs;
    bool is_real_policy_session;
    bool is_session_encryption_required;
    bool is_session_audit_required;
};

static tpm2_startauthsession_ctx ctx = {
    .session = {
        .type = TPM2_SE_TRIAL,
        .halg = TPM2_ALG_SHA256
    }
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 0:
        ctx.is_real_policy_session = true;
        break;
    case 1:
        ctx.is_session_audit_required = true;
        break;
    case 'g':
        ctx.session.halg = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_hash);
        if (ctx.session.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'S':
        ctx.output.path = value;
        break;
    case 'c':
        ctx.session.key_context_arg_str = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy-session", no_argument,       NULL,  0 },
        { "audit-session",  no_argument,       NULL,  1 },
        { "key-context",    required_argument, NULL, 'c'},
        { "hash-algorithm", required_argument, NULL, 'g'},
        { "session",        required_argument, NULL, 'S'},
    };

    *opts = tpm2_options_new("g:S:c:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static tool_rc is_input_options_valid(void) {

    if (!ctx.output.path) {
        LOG_ERR("Expected option -S");
        return tool_rc_option_error;
    }

    if (!ctx.is_real_policy_session && !ctx.is_session_audit_required &&
    ctx.session.key_context_arg_str) {
        LOG_ERR("Trial sessions cannot be additionally used as encrypt/decrypt "
                "session");
        return tool_rc_option_error;
    }

    if (ctx.is_real_policy_session && ctx.is_session_audit_required) {
        LOG_ERR("Policy sessions cannot be additionally used for audit");
        return tool_rc_option_error;
    }

    if (ctx.is_session_audit_required) {
        LOG_WARN("Starting an HMAC session for use with auditing.");
    }

    return tool_rc_success;
}

static tool_rc setup_session_data(void) {

    if (ctx.is_real_policy_session) {
        ctx.session.type = TPM2_SE_POLICY;
    }

    if (ctx.is_session_audit_required) {
        ctx.session.type = TPM2_SE_HMAC;
    }


    ctx.session_data = tpm2_session_data_new(ctx.session.type);
    if (!ctx.session_data) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    tpm2_session_set_path(ctx.session_data, ctx.output.path);

    tpm2_session_set_authhash(ctx.session_data, ctx.session.halg);

    /* if it has an encryption key, set it as both the encryption key and bind key */
    if (ctx.is_session_encryption_required) {
        tpm2_session_set_key(ctx.session_data,
                ctx.session.key_context_object.tr_handle);
        tpm2_session_set_bind(ctx.session_data,
                ctx.session.key_context_object.tr_handle);

        TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_AES, .keyBits =
                { .aes = 128 }, .mode = { .aes = TPM2_ALG_CFB } };

        tpm2_session_set_symmetric(ctx.session_data, &sym);

        ctx.attrs = TPMA_SESSION_CONTINUESESSION | \
                    TPMA_SESSION_DECRYPT | \
                    TPMA_SESSION_ENCRYPT;
    }

    ctx.attrs |= ctx.is_session_audit_required ?
                 TPMA_SESSION_CONTINUESESSION|TPMA_SESSION_AUDIT : 0;

    if (ctx.is_session_audit_required || ctx.is_session_encryption_required) {
        tpm2_session_set_attrs(ctx.session_data, ctx.attrs);
    }

    return tool_rc_success;
}

static tool_rc process_input_data(ESYS_CONTEXT *ectx) {

    /*
     * attempt to set up the encryption parameters for this, we load an ESYS_TR from disk for
     * transient objects and we load from tpm public for persistent objects. Deserialized ESYS TR
     * objects are checked.
     */
    if (ctx.session.key_context_arg_str) {
        tool_rc rc = tpm2_util_object_load(ectx,
                ctx.session.key_context_arg_str,
                &ctx.session.key_context_object, TPM2_HANDLE_ALL_W_NV);
        if (rc != tool_rc_success) {
            return rc;
        }
        ctx.is_session_encryption_required = true;

        /* if the loaded object has a handle then it must be a persistent object */
        if (ctx.session.key_context_object.handle) {

            bool is_transient = (ctx.session.key_context_object.handle
                    >> TPM2_HR_SHIFT) == TPM2_HT_TRANSIENT;
            if (!is_transient) {
                LOG_WARN("check public key portion manually");
            }
        }
    }

    return setup_session_data();
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    //Check input options
    tool_rc rc = is_input_options_valid();
    if (rc != tool_rc_success) {
        return rc;
    }

    //Process inputs
    rc = process_input_data(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    //ESAPI call to start session
    tpm2_session *s = NULL;
    rc = tpm2_session_open(ectx, ctx.session_data, &s);
    if (rc != tool_rc_success) {
        return rc;
    }

    //Process outputs
    return tpm2_session_close(&s);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("startauthsession", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
