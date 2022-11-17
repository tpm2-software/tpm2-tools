/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm2_startauthsession_ctx tpm2_startauthsession_ctx;
struct tpm2_startauthsession_ctx {
    struct {
        TPM2_SE type;
        TPMI_ALG_HASH halg;
        TPMT_SYM_DEF sym;
        struct {
            /*
             * Salt generated by esys is encrypted using the tpmkey and
             * encryption does not require auth to be specified.
             */
            const char *key_context_arg_str;
            tpm2_loaded_object key_context_object;
        } tpmkey;

        struct {
            /*
             * While TPM2_CC_StartAuthSession does not required the auth of the
             * bind to be specified, it is captured here for esys to calculate
             * the sessionkey.
             */
            const char *bind_context_arg_str;
            const char *bind_context_auth_str;
            tpm2_loaded_object bind_context_object;
        } bind;
    } session;
    struct {
        const char *path;
    } output;

    tpm2_session_data *session_data;
    TPMA_SESSION attrs;
    bool is_real_policy_session;
    bool is_hmac_session;
    bool is_session_encryption_possibly_needed;
    bool is_session_audit_required;
    /* Salted/ Bounded session combinations */
    bool is_salted;
    bool is_bounded;
    bool is_salt_and_bind_obj_same;

    const char *name_path;
    TPM2B_NAME name;
};

static tpm2_startauthsession_ctx ctx = {
    .attrs = TPMA_SESSION_CONTINUESESSION,
    .session = {
        .type = TPM2_SE_TRIAL,
        .halg = TPM2_ALG_SHA256,
        .sym = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = { .aes = 128 },
            .mode = { .aes = TPM2_ALG_CFB }
        },
    },
    .name = {
        .size = BUFFER_SIZE(TPM2B_NAME, name)
    },
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 0:
        ctx.is_real_policy_session = true;
        break;
    case 1:
        ctx.is_hmac_session = true;
        ctx.is_session_audit_required = true;
        ctx.attrs |= TPMA_SESSION_AUDIT;
        break;
    case 'g':
        ctx.session.halg = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_hash);
        if (ctx.session.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'G':
        ctx.session.sym.algorithm = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_symmetric);
        if (ctx.session.sym.algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid symmetric algorithm");
            return false;
        }
        break;
    case 'S':
        ctx.output.path = value;
        break;
    case 'c':
        ctx.is_salt_and_bind_obj_same = true;
        ctx.session.tpmkey.key_context_arg_str = value;
        ctx.session.bind.bind_context_arg_str = value;
        ctx.is_session_encryption_possibly_needed = true;
        ctx.attrs |= (TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT);
        break;
    case 'n':
        ctx.name_path = value;
        break;
    case 2:
        ctx.is_bounded = true;
        ctx.session.bind.bind_context_arg_str = value;
        ctx.is_session_encryption_possibly_needed = true;
        break;
    case 3:
        ctx.session.bind.bind_context_auth_str = value;
        break;
    case 4:
        ctx.is_salted = true;
        ctx.session.tpmkey.key_context_arg_str = value;
        ctx.is_session_encryption_possibly_needed = true;
        break;
    case 5:
        ctx.is_hmac_session = true;
        ctx.is_session_encryption_possibly_needed = true;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy-session", no_argument,       NULL,  0 },
        { "audit-session",  no_argument,       NULL,  1 },
        { "bind-context",   required_argument, NULL,  2 },
        { "bind-auth",      required_argument, NULL,  3 },
        { "tpmkey-context", required_argument, NULL,  4 },
        { "hmac-session",   no_argument,       NULL,  5 },
        { "hash-algorithm", required_argument, NULL, 'g'},
        { "key-algorithm",  required_argument, NULL, 'G'},
        { "session",        required_argument, NULL, 'S'},
        { "key-context",    required_argument, NULL, 'c'},
        { "name",           required_argument, NULL, 'n'},
    };

    *opts = tpm2_options_new("g:G:S:c:n:", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static tool_rc is_input_options_valid(void) {

    if (!ctx.output.path) {
        LOG_ERR("Expected option -S");
        return tool_rc_option_error;
    }

    /* Trial-session: neither real_policy nor audit/hmac session */
    if (!ctx.is_real_policy_session && !ctx.is_hmac_session &&
    ctx.is_session_encryption_possibly_needed) {
        LOG_ERR("Trial sessions cannot be additionally used as encrypt/decrypt "
                "session");
        return tool_rc_option_error;
    }

    /*
     * Only use --key-context if both bind and tpmkey objects are the same.
     */
    if (ctx.is_salted && ctx.is_salt_and_bind_obj_same) {
        LOG_ERR("Specify --key-context or tpmkey-context, not both.");
        return tool_rc_option_error;
    }

    if (ctx.is_bounded && ctx.is_salt_and_bind_obj_same) {
        LOG_ERR("Specify --key-context or --bind-context, not both.");
        return tool_rc_option_error;
    }

    if (ctx.session.bind.bind_context_auth_str &&
    !ctx.session.bind.bind_context_arg_str) {
        LOG_ERR("Specify the bind entity when specifying the bind auth "
                "even when bind is same as tpmkey object.");
        return tool_rc_option_error;
    }

    /*
     * Setting sessions for audit should be handled with tpm2_sessionconfig
     * The following support is for backwards compatibility
     */
    if (ctx.is_real_policy_session && ctx.is_session_audit_required) {
        LOG_ERR("Policy sessions cannot be additionally used for audit");
        return tool_rc_option_error;
    }

    /*
     * A session cannot be without a purpose.
     */
    if (!(ctx.attrs & TPMA_SESSION_AUDIT) &&
    !(ctx.attrs & TPMA_SESSION_ENCRYPT) &&
    !(ctx.attrs & TPMA_SESSION_DECRYPT) && ctx.is_hmac_session) {
        LOG_WARN("Session has to be used either for auth and/or audit and/or "
                 "parameter-encryption/decryption. Use session-config tool to "
                 "specify the use");
    }

    return tool_rc_success;
}

static tool_rc setup_session_data(void) {

    if (ctx.is_real_policy_session) {
        ctx.session.type = TPM2_SE_POLICY;
    }

    if (ctx.is_hmac_session) {
        ctx.session.type = TPM2_SE_HMAC;
    }

    ctx.session_data = tpm2_session_data_new(ctx.session.type);
    if (!ctx.session_data) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    tpm2_session_set_path(ctx.session_data, ctx.output.path);

    tpm2_session_set_authhash(ctx.session_data, ctx.session.halg);

    if (ctx.is_session_encryption_possibly_needed) {

        tpm2_session_set_symmetric(ctx.session_data, &ctx.session.sym);
    }

    if (ctx.session.bind.bind_context_arg_str) {
        tpm2_session_set_bind(ctx.session_data,
        ctx.session.bind.bind_context_object.tr_handle);
    }

    if (ctx.session.tpmkey.key_context_arg_str) {
        tpm2_session_set_key(ctx.session_data,
        ctx.session.tpmkey.key_context_object.tr_handle);
    }

    tpm2_session_set_attrs(ctx.session_data, ctx.attrs);

    return tool_rc_success;
}

static tool_rc process_input_data(ESYS_CONTEXT *ectx) {

    if (ctx.name_path) {
        bool ret = files_load_bytes_from_path(ctx.name_path, ctx.name.name, &ctx.name.size);
        if (!ret) {
            LOG_ERR("Could load name from path: \"%s\"", ctx.name_path);
            return tool_rc_general_error;
        }
    }

    /*
     * Backwards compatibility behavior/ side-effect:
     *
     * The presence of a tpmkey and bind object should not result in setting up
     * the session for parameter encryption. It is not a requirement. IOW one
     * can have a salted and bounded session and not perform parameter
     * encryption.
     */

    if (ctx.session.tpmkey.key_context_arg_str) {
    /*
     * attempt to set up the encryption parameters for this, we load an ESYS_TR
     * from disk for transient objects and we load from tpm public for
     * persistent objects. Deserialized ESYS TR objects are checked.
     */
        tool_rc rc = tpm2_util_object_load(ectx,
                ctx.session.tpmkey.key_context_arg_str,
                &ctx.session.tpmkey.key_context_object, TPM2_HANDLE_ALL_W_NV);
        if (rc != tool_rc_success) {
            return rc;
        }

        /* if loaded object is non-permanant, it should ideally be persistent */
        if (ctx.session.tpmkey.key_context_object.handle) {

            bool is_transient = (ctx.session.tpmkey.key_context_object.handle
                    >> TPM2_HR_SHIFT) == TPM2_HT_TRANSIENT;
            if (!is_transient && !ctx.name_path) {
                LOG_WARN("check public portion of the tpmkey manually");
            }

            /*
             * ESAPI performs this check when an ESYS_TR or Context file is used, so we
             * could only run the check on the case where a raw TPM handle is provided,
             * however, it seems prudent that if the user specifies a name, we always
             * just check it.
             */
            if (ctx.name_path) {
                TPM2B_NAME *got_name = NULL;
                rc = tpm2_tr_get_name(ectx, ctx.session.tpmkey.key_context_object.tr_handle,
                        &got_name);
                if (rc != tool_rc_success) {
                    return rc;
                }

                bool is_expected = cmp_tpm2b(name, &ctx.name, got_name);
                Esys_Free(got_name);
                if (!is_expected) {
                    LOG_ERR("Expected name does not match");
                    return tool_rc_general_error;
                }
            }
        }
    }

    /*
     * We need to load the bind object and set its auth value in the bind
     * objects ESYS_TR.
     *
     * A loaded object creates another session and that is not what we want.
     */
    if (ctx.session.bind.bind_context_arg_str) {
        tool_rc rc = tpm2_util_object_load(ectx,
                ctx.session.bind.bind_context_arg_str,
                &ctx.session.bind.bind_context_object, TPM2_HANDLE_ALL_W_NV);
        if (rc != tool_rc_success) {
            return rc;
         }
    }

    if (ctx.session.bind.bind_context_auth_str) {
        TPM2B_AUTH authvalue = { 0 };
        bool result = handle_str_password(
            ctx.session.bind.bind_context_auth_str, &authvalue);
        if (!result) {
            return tool_rc_general_error;
        }

        tool_rc rc = tpm2_tr_set_auth(ectx,
        ctx.session.bind.bind_context_object.tr_handle, &authvalue);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed setting auth in the bind object ESYS_TR");
            return rc;
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
TPM2_TOOL_REGISTER("startauthsession", tpm2_tool_onstart, tpm2_tool_onrun, NULL,
NULL)
