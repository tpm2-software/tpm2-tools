/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

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
        ctx.session.type = TPM2_SE_POLICY;
        break;
    case 'g':
        ctx.session.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if(ctx.session.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for policy digest hash algorithm");
            return false;
        }
        break;
    case 'S':
        ctx.output.path = value;
        break;
    case 'k':
        ctx.session.key_context_arg_str = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy-session",      no_argument,       NULL,  0 },
        { "key",                 required_argument, NULL, 'k'},
        { "halg",                required_argument, NULL, 'g'},
        { "session",             required_argument, NULL, 'S'},
    };

    *opts = tpm2_options_new("g:S:k:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tool_rc_general_error;

    /*
     * attempt to set up the encryption parameters for this, we load an ESYS_TR from disk for
     * transient objects and we load from tpm public for persistent objects. Deserialized ESYS TR
     * objects are checked.
     */
    bool has_key = false;

    if (!ctx.output.path) {
        LOG_ERR("Expected option -S");
        return tool_rc_option_error;
    }

    if (ctx.session.key_context_arg_str) {
        tool_rc tmp_rc = tpm2_util_object_load(ectx, ctx.session.key_context_arg_str,
                                    &ctx.session.key_context_object);
        if (tmp_rc != tool_rc_success) {
            return tmp_rc;
        }

        bool is_persistent = false;
        /* if the loaded object has a handle then it must be a persistent object */
        if (ctx.session.key_context_object.handle) {

            is_persistent = (ctx.session.key_context_object.handle >> TPM2_HR_SHIFT) == TPM2_HT_PERSISTENT;
            if (!is_persistent) {
                LOG_ERR("Specified encryption key not a persistent object, got: %s", ctx.session.key_context_arg_str);
                return rc;
            }

            LOG_WARN("check public key portion");
        }

        has_key = true;
    }

    tpm2_session_data *session_data = tpm2_session_data_new(ctx.session.type);
    if (!session_data) {
        LOG_ERR("oom");
        return rc;
    }

    tpm2_session_set_path(session_data, ctx.output.path);

    tpm2_session_set_authhash(session_data, ctx.session.halg);

    /* if it has an encryption key, set it as both the encryption key and bind key */
    if (has_key) {
        tpm2_session_set_key(session_data, ctx.session.key_context_object.tr_handle);
        tpm2_session_set_bind(session_data, ctx.session.key_context_object.tr_handle);

        TPMT_SYM_DEF sym = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = { .aes = 128 },
            .mode = { .aes = TPM2_ALG_CFB }
        };

        tpm2_session_set_symmetric(session_data, &sym);

        TPMA_SESSION attrs =
            TPMA_SESSION_CONTINUESESSION
          | TPMA_SESSION_DECRYPT
          | TPMA_SESSION_ENCRYPT;

        tpm2_session_set_attrs(session_data, attrs);
    }

    tpm2_session *s = NULL;
    rc = tpm2_session_open(ectx,
            session_data, &s);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tpm2_session_close(&s);
}
