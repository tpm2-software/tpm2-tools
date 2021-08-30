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
    (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH)

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

static void setup_default_attrs(TPMA_OBJECT *attrs, bool has_policy, bool has_auth) {

    /* Handle Default Setup */
    *attrs = BASE_DEFAULT_ATTRS;

    if (has_policy && !has_auth) {
        *attrs &= ~TPMA_OBJECT_USERWITHAUTH;
    }
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

    TPMA_OBJECT def_attrs = 0;
    if (!ctx.attrs) {
        setup_default_attrs(&def_attrs, !!ctx.policy, !!ctx.auth);
    }

    /*
     * Set the AUTH value for sensitive portion
     */
    TPM2B_SENSITIVE priv = { 0 };

    /*
     * Load the users specified public object if specified via -u
     */
    TPM2B_PUBLIC pub = { 0 };

    /*
     * Input values are public assumed to be in the TSS format unless:
     * 1. A private (TPM2B_PRIVATE) key is specified. Since a TPM2B_PRIVATE is nonsense to load externally.
     * 2. The key_type is specified indicated you want to load an external public raw key of some type
     * 3. The third option is no public, which means the public could be coming from a private PEM file
     *
     */
    if (!ctx.key_type && ctx.public_key_path) {
        /* Load TSS */
        bool result = files_load_public(ctx.public_key_path, &pub);
        if (!result) {
            return tool_rc_general_error;
        }

        /* overwrite certain things here */
        if (ctx.name_alg) {
            pub.publicArea.nameAlg = tpm2_alg_util_from_optarg(ctx.name_alg, tpm2_alg_util_flags_hash);
            if (pub.publicArea.nameAlg == TPM2_ALG_ERROR) {
                LOG_ERR("Invalid name hashing algorithm, got\"%s\"", ctx.name_alg);
                return tool_rc_unsupported;
            }
        }

        if (ctx.attrs) {
            bool res = tpm2_attr_util_obj_from_optarg(ctx.attrs,
                    &pub.publicArea.objectAttributes);
            if (!res) {
                return tool_rc_unsupported;
            }
        }

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


    } else if (ctx.public_key_path || ctx.key_type) {
        /* Load RAW public */
        TPM2B_PUBLIC template = { 0 };
        tool_rc rc = tpm2_alg_util_public_init(ctx.key_type, ctx.name_alg,
            ctx.attrs, ctx.policy, def_attrs, &template);
        if (rc != tool_rc_success) {
            return rc;
        }

        pub = template;

        if (ctx.public_key_path) {
            /* Get the public from a RAW source, ie PEM */
            bool result = tpm2_openssl_load_public(ctx.public_key_path, template.publicArea.type, &pub);
            if (!result) {
                return tool_rc_general_error;
            }
        }
    } else {
        LOG_ERR("Unkown internal state");
        return tool_rc_general_error;
    }

    /*
     * Okay, we have the public portion in some form, at a minimum a template and at a maximum a fully specified
     * public, load the private portion.
     */
    if (ctx.private_key_path) {
        /*
         * when nameAlg is not TPM2_ALG_NULL, seed value is needed to pass
         * consistency checks by TPM
         */
        TPM2B_DIGEST *seed = &priv.sensitiveArea.seedValue;
        seed->size = tpm2_alg_util_get_hash_size(pub.publicArea.nameAlg);
        if (seed->size != 0) {
            RAND_bytes(seed->buffer, seed->size);
        }

        tpm2_openssl_load_rc load_status = tpm2_openssl_load_private(
            ctx.private_key_path, ctx.passin, ctx.auth, &pub, &pub, &priv);
        if (load_status == lprc_error) {
            return tool_rc_general_error;
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

            /* Okay... we got two publics, use the user specified one and issue a warning */
            LOG_WARN("Loaded a public key from the private portion"
                    " and a public portion was specified via -u. Defaulting"
                    " to specified public");

            /*
             * This effectively turns off cryptographic binding between
             * public and private portions of the object. Since we got a public portion
             * from the
             */
            pub.publicArea.nameAlg = TPM2_ALG_NULL;
        }
    }

    TPM2B_NAME *name = NULL;
    tool_rc rc = load_external(ectx, &pub, &priv, ctx.private_key_path != NULL,
            &name);
    if (rc != tool_rc_success) {
        goto out;
    }

    assert(name);

    rc = files_save_tpm_context_to_path(ectx, ctx.handle,
            ctx.context_file_path);
    if (rc != tool_rc_success) {
        goto out;
    }

    tpm2_tool_output("name: ");
    tpm2_util_hexdump(name->name, name->size);
    tpm2_tool_output("\n");

    if (ctx.name_path) {
        bool result = files_save_bytes_to_file(ctx.name_path, name->name,
                name->size);
        if (!result) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

out:
    free(name);

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("loadexternal", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
