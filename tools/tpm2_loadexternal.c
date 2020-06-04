/* SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_openssl.h"
#include "tpm2_tool.h"

#define BASE_DEFAULT_ATTRS \
    (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT)

#define DEFAULT_NAME_ALG TPM2_ALG_SHA256

typedef struct tpm_loadexternal_ctx tpm_loadexternal_ctx;
struct tpm_loadexternal_ctx {
    char *context_file_path;
    TPMI_RH_HIERARCHY hierarchy_value;
    ESYS_TR handle;
    char *public_key_path; /* path to the public portion of an object */
    char *private_key_path; /* path to the private portion of an object */
    char *attrs; /* The attributes to use */
    char *auth; /* The password for use of the private portion */
    char *policy; /* a policy for use of the private portion */
    char *name_alg; /* name hashing algorithm */
    char *key_type; /* type of key attempting to load, defaults to an auto attempt */
    char *name_path; /* An optional path to output the loaded objects name information to */
    char *passin; /* an optional auth string for the input key file for OSSL */
};

static tpm_loadexternal_ctx ctx = {
    /*
     * default to the NULL hierarchy, as the tpm rejects loading a private
     * portion of an object in other hierarchies.
     */
    .hierarchy_value = TPM2_RH_NULL,
};

static tool_rc load_external(ESYS_CONTEXT *ectx, TPM2B_PUBLIC *pub,
        TPM2B_SENSITIVE *priv, bool has_priv, TPM2B_NAME **name) {

    uint32_t hierarchy;
    TSS2_RC rval = fix_esys_hierarchy(ctx.hierarchy_value, &hierarchy);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERR("Unknown hierarchy");
        return tool_rc_from_tpm(rval);
    }

    tool_rc rc = tpm2_loadexternal(ectx,
            has_priv ? priv : NULL, pub,
            hierarchy, &ctx.handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    return tpm2_tr_get_name(ectx, ctx.handle, name);
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'C':
        result = tpm2_util_handle_from_optarg(value, &ctx.hierarchy_value,
                TPM2_HANDLE_FLAGS_ALL_HIERACHIES);
        if (!result) {
            return false;
        }
        break;
    case 'u':
        ctx.public_key_path = value;
        break;
    case 'r':
        ctx.private_key_path = value;
        break;
    case 'c':
        ctx.context_file_path = value;
        break;
    case 'a':
        ctx.attrs = value;
        break;
    case 'p':
        ctx.auth = value;
        break;
    case 'L':
        ctx.policy = value;
        break;
    case 'g':
        ctx.name_alg = value;
        break;
    case 'G':
        ctx.key_type = value;
        break;
    case 'n':
        ctx.name_path = value;
        break;
    case 0:
        ctx.passin = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",      required_argument, NULL, 'C'},
      { "public",         required_argument, NULL, 'u'},
      { "private",        required_argument, NULL, 'r'},
      { "key-context",    required_argument, NULL, 'c'},
      { "attributes",     required_argument, NULL, 'a'},
      { "policy",         required_argument, NULL, 'L'},
      { "auth",           required_argument, NULL, 'p'},
      { "hash-algorithm", required_argument, NULL, 'g'},
      { "key-algorithm",  required_argument, NULL, 'G'},
      { "name",           required_argument, NULL, 'n'},
      { "passin",         required_argument, NULL,  0 },
    };

    *opts = tpm2_options_new("C:u:r:c:a:p:L:g:G:n:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!ctx.public_key_path && !ctx.private_key_path) {
        LOG_ERR("Expected either -r or -u options");
        return tool_rc_option_error;
    }

    if (!ctx.context_file_path) {
        LOG_ERR("Expected -c option");
        return tool_rc_option_error;
    }

    /*
     * We only load a TSS format for the public portion, so if
     * someone hands us a public file, we'll assume the TSS format when
     * no -G is specified.
     *
     * If they specify a private they need to tell us the type we expect.
     * This helps reduce auto-guess complexity, as well as future proofing
     * us for being able to load XOR. Ie we don't want to guess XOR or HMAC
     * in leui of AES or vice versa.
     */
    if (!ctx.key_type && ctx.private_key_path) {
        LOG_ERR("Expected key type via -G option when specifying private"
                " portion of object");
        return tool_rc_option_error;
    }

    TPMI_ALG_PUBLIC alg = TPM2_ALG_NULL;

    if (ctx.key_type) {
        alg = tpm2_alg_util_from_optarg(ctx.key_type,
                tpm2_alg_util_flags_asymmetric | tpm2_alg_util_flags_symmetric);
        if (alg == TPM2_ALG_ERROR) {
            LOG_ERR("Unsupported key type, got: \"%s\"", ctx.key_type);
            return tool_rc_general_error;
        }
    }

    /*
     * Modifying this init to anything NOT 0 requires
     * the memset/reinit on the case of specified -u
     * and found public data in private.
     */
    TPM2B_PUBLIC pub = {
        . size = 0,
        .publicArea = {
            .authPolicy = { .size = 0 },
        },
    };

    /*
     * set up the public attributes with a default.
     * This can be cleared by load_public() if a TSS
     * object is provided.
     */
    if (ctx.attrs) {
        bool result = tpm2_attr_util_obj_from_optarg(ctx.attrs,
                &pub.publicArea.objectAttributes);
        if (!result) {
            return tool_rc_general_error;
        }
    } else {
        /*
         * Default to the BASE attributes, but add in USER_WITH_AUTH if -p is specified
         * or NO -L. Where -L is a specified policy and -p is a specified password.
         * Truth Table:
         * -L -p | Result
         * --------------
         *  0  0 | 1 (set USER_WITH_AUTH)
         *  0  1 | 0 (don't set USER_WITH_AUTH) <-- we want this case.
         *  1  0 | 1
         *  1  1 | 1
         *
         * This is an if/then truth table, we want to execute setting USER_WITH_AUTH on
         * it's negation.
         */
        pub.publicArea.objectAttributes = BASE_DEFAULT_ATTRS;
        if (!(ctx.policy && !ctx.auth)) {
            pub.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
        }
    }

    /*
     * Set the policy for public, again this can be overridden if the
     * object is a TSS object
     */
    if (ctx.policy) {
        pub.publicArea.authPolicy.size =
                sizeof(pub.publicArea.authPolicy.buffer);
        bool res = files_load_bytes_from_path(ctx.policy,
                pub.publicArea.authPolicy.buffer,
                &pub.publicArea.authPolicy.size);
        if (!res) {
            return tool_rc_general_error;
        }
    }

    /*
     * Set the name alg, again this gets wipped on a TSS object
     */
    pub.publicArea.nameAlg =
        ctx.name_alg ?
                    tpm2_alg_util_from_optarg(ctx.name_alg,
                            tpm2_alg_util_flags_hash
                                    | tpm2_alg_util_flags_misc) :
                    DEFAULT_NAME_ALG;
    if (pub.publicArea.nameAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid name hashing algorithm, got: \"%s\"", ctx.name_alg);
        return tool_rc_general_error;
    }

    /*
     * Set the AUTH value for sensitive portion
     */
    TPM2B_SENSITIVE priv = {
        .size = 0,
        .sensitiveArea = {
            .authValue = { .size = 0 }
        },
    };
    /*
     * when nameAlg is not TPM2_ALG_NULL, seed value is needed to pass
     * consistency checks by TPM
     */
    TPM2B_DIGEST *seed = &priv.sensitiveArea.seedValue;
    seed->size = tpm2_alg_util_get_hash_size(pub.publicArea.nameAlg);
    if (seed->size != 0) {
        RAND_bytes(seed->buffer, seed->size);
    }

    tpm2_session *tmp;
    tool_rc tmp_rc = tpm2_auth_util_from_optarg(NULL, ctx.auth, &tmp, true);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return tmp_rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    priv.sensitiveArea.authValue = *auth;

    tpm2_session_close(&tmp);

    tpm2_openssl_load_rc load_status = lprc_error;
    if (ctx.private_key_path) {
        load_status = tpm2_openssl_load_private(ctx.private_key_path,
                ctx.passin, alg, &pub, &priv);
        if (load_status == lprc_error) {
            return tool_rc_general_error;
        }
    }

    /*
     * If we cannot load the public from the private and a path
     * is not specified for public, this is an error.
     *
     * If we loaded the public from the private and a public was
     * specified, this is warning. re-init public and load the
     * specified one.
     */
    if (!tpm2_openssl_did_load_public(load_status) && !ctx.public_key_path) {
        LOG_ERR("Only loaded a private key, expected public key in either"
                " private PEM or -r option");
        return tool_rc_general_error;

    } else if (tpm2_openssl_did_load_public(load_status)
            && ctx.public_key_path) {
        LOG_WARN("Loaded a public key from the private portion"
                " and a public portion was specified via -u. Defaulting"
                " to specified public");

        memset(&pub.publicArea.parameters, 0,
                sizeof(pub.publicArea.parameters));
        pub.publicArea.type = TPM2_ALG_NULL;
    }

    if (ctx.public_key_path) {
        bool result = tpm2_openssl_load_public(ctx.public_key_path, alg, &pub);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_general_error;
    TPM2B_NAME *name = NULL;
    tmp_rc = load_external(ectx, &pub, &priv, ctx.private_key_path != NULL,
            &name);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out;
    }

    assert(name);

    tmp_rc = files_save_tpm_context_to_path(ectx, ctx.handle,
            ctx.context_file_path);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out;
    }

    tpm2_tool_output("name: ");
    tpm2_util_hexdump(name->name, name->size);
    tpm2_tool_output("\n");

    if (ctx.name_path) {
        bool result = files_save_bytes_to_file(ctx.name_path, name->name,
                name->size);
        if (!result) {
            goto out;
        }
    }

    rc = tool_rc_success;

out:
    free(name);

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("loadexternal", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
