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
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "object.h"

#define MAX_SESSIONS 3
typedef struct tpm_loadexternal_ctx tpm_loadexternal_ctx;
struct tpm_loadexternal_ctx {
    /*
     * Inputs
     */
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
    TPM2B_SENSITIVE priv; /* Set the AUTH value for sensitive portion */
    TPM2B_PUBLIC pub; /* Load the users specified public object if specified via -u*/
    bool autoflush; /* Flush the object after creation of the ctx file */
    /*
     * TSS Privkey related
     */
    bool is_tsspem;

    /*
     * Outputs
     */
    char *context_file_path;
    TPM2B_NAME *name;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_loadexternal_ctx ctx = {
    /*
     * default to the NULL hierarchy, as the tpm rejects loading a private
     * portion of an object in other hierarchies.
     */
    .hierarchy_value = TPM2_RH_NULL,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
    .autoflush = false,
};

static tool_rc load_external(ESYS_CONTEXT *ectx) {

    bool is_priv_specified = (ctx.private_key_path != 0 && !ctx.is_tsspem);
    return tpm2_loadexternal(ectx, is_priv_specified ? &ctx.priv : 0, &ctx.pub,
        ctx.hierarchy_value, &ctx.handle, &ctx.cp_hash,
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

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    rc = tpm2_tr_get_name(ectx, ctx.handle, &ctx.name);
    if (rc != tool_rc_success) {
        return rc;
    }
    assert(ctx.name);

    rc = files_save_tpm_context_to_path(ectx, ctx.handle,
         ctx.context_file_path, ctx.autoflush);
    if (rc != tool_rc_success) {
        goto out;
    }

    tpm2_tool_output("name: ");
    tpm2_util_hexdump(ctx.name->name, ctx.name->size);
    tpm2_tool_output("\n");

    if (ctx.name_path) {
        bool result = files_save_bytes_to_file(ctx.name_path, ctx.name->name,
            ctx.name->size);
        if (!result) {
            rc = tool_rc_general_error;
            goto out;
        }
    }

out:
    free(ctx.name);

    return rc;
}

#define BASE_DEFAULT_ATTRS \
    (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH)

static void setup_default_attrs(TPMA_OBJECT *attrs, bool has_policy,
    bool has_auth) {

    /* Handle Default Setup */
    *attrs = BASE_DEFAULT_ATTRS;

    if (has_policy && !has_auth) {
        *attrs &= ~TPMA_OBJECT_USERWITHAUTH;
    }
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    TPMA_OBJECT def_attrs = 0;
    if (!ctx.attrs) {
        setup_default_attrs(&def_attrs, !!ctx.policy, !!ctx.auth);
    }

    tool_rc rc = tool_rc_success;
    if (ctx.is_tsspem) {
        /* Fetch and set public */
        TPM2B_PRIVATE priv = { 0 };
        rc = tpm2_util_object_fetch_priv_pub_from_tpk(ctx.private_key_path,
            &ctx.pub, &priv);
        if (rc != tool_rc_success) {
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
            LOG_ERR("Expected key type via -G option when specifying private"
                    " portion of object that is not in tssprivkey format");
            return rc;
        }

        goto priv_path;
    }

    /*
     * Input values are public assumed to be in the TSS format unless:
     * 1. A private (TPM2B_PRIVATE) key is specified. Since a TPM2B_PRIVATE is
     *    nonsense to load externally.
     * 2. The key_type is specified indicated you want to load an external
     *    public raw key of some type
     * 3. The third option is no public, which means the public could be coming
     *    from a private PEM file
     */
    if (!ctx.key_type && ctx.public_key_path) {
        /* Load TSS */
        bool result = files_load_public(ctx.public_key_path, &ctx.pub);
        if (!result) {
            return tool_rc_general_error;
        }

        /* overwrite certain things here */
        if (ctx.name_alg) {
            ctx.pub.publicArea.nameAlg = tpm2_alg_util_from_optarg(ctx.name_alg,
                tpm2_alg_util_flags_hash);
            if (ctx.pub.publicArea.nameAlg == TPM2_ALG_ERROR) {
                LOG_ERR("Invalid name hashing algorithm, got\"%s\"",
                    ctx.name_alg);
                return tool_rc_unsupported;
            }
        }

        if (ctx.attrs) {
            bool res = tpm2_attr_util_obj_from_optarg(ctx.attrs,
                    &ctx.pub.publicArea.objectAttributes);
            if (!res) {
                return tool_rc_unsupported;
            }
        }

        if (ctx.policy) {
            rc = tpm2_policy_set_digest(ctx.policy,
                    &ctx.pub.publicArea.authPolicy);
            if (rc != tool_rc_success) {
                return rc;
            }
        }


    } else if (ctx.public_key_path || ctx.key_type) {
        /* Load RAW public */
        TPM2B_PUBLIC template = { 0 };
        rc = tpm2_alg_util_public_init(ctx.key_type, ctx.name_alg,
            ctx.attrs, ctx.policy, def_attrs, &template);
        if (rc != tool_rc_success) {
            return rc;
        }

        ctx.pub = template;

        if (ctx.public_key_path) {
            /* Get the public from a RAW source, ie PEM */
            bool result = tpm2_openssl_load_public(ctx.public_key_path,
                template.publicArea.type, &ctx.pub);
            if (!result) {
                return tool_rc_general_error;
            }
        }
    } else {
        LOG_ERR("Unkown internal state");
        return tool_rc_general_error;
    }

priv_path:
    /*
     * Okay, we have the public portion in some form, at a minimum a template
     * and at a maximum a fully specified public, load the private portion.
     */
    if (ctx.private_key_path && !ctx.is_tsspem) {
        /*
         * when nameAlg is not TPM2_ALG_NULL, seed value is needed to pass
         * consistency checks by TPM
         */
        TPM2B_DIGEST *seed = &ctx.priv.sensitiveArea.seedValue;
        seed->size = tpm2_alg_util_get_hash_size(ctx.pub.publicArea.nameAlg);
        if (seed->size != 0) {
            RAND_bytes(seed->buffer, seed->size);
        }

        tpm2_openssl_load_rc load_status = tpm2_openssl_load_private(
            ctx.private_key_path, ctx.passin, ctx.auth, &ctx.pub, &ctx.pub,
            &ctx.priv);
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
        bool is_ossl_pub_load = tpm2_openssl_did_load_public(load_status);
        if (!is_ossl_pub_load && !ctx.public_key_path) {
            LOG_ERR("Only loaded a private key, expected public key in either"
                    " private PEM or -r option");
            return tool_rc_general_error;
        }

        if (is_ossl_pub_load && ctx.public_key_path) {
            /*
             * Okay... we got two publics, use the user specified one and
             * issue a warning
             */
            LOG_WARN("Loaded a public key from the private portion"
                    " and a public portion was specified via -u. Defaulting"
                    " to specified public");

            /*
             * This effectively turns off cryptographic binding between
             * public and private portions of the object.
             */
            ctx.pub.publicArea.nameAlg = TPM2_ALG_NULL;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        0,
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

    if (!ctx.public_key_path && !ctx.private_key_path) {
        LOG_ERR("Expected either -r or -u options");
        return tool_rc_option_error;
    }

    if (!ctx.context_file_path && !ctx.cp_hash_path) {
        LOG_ERR("Expected -c option");
        return tool_rc_option_error;
    }

    ctx.is_tsspem = (!ctx.key_type && ctx.private_key_path);

    return tool_rc_success;
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
    case 1:
        ctx.cp_hash_path = value;
        break;
    case 'R':
        ctx.autoflush = true;
        break; 
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",      required_argument, 0, 'C'},
      { "public",         required_argument, 0, 'u'},
      { "private",        required_argument, 0, 'r'},
      { "key-context",    required_argument, 0, 'c'},
      { "attributes",     required_argument, 0, 'a'},
      { "policy",         required_argument, 0, 'L'},
      { "auth",           required_argument, 0, 'p'},
      { "hash-algorithm", required_argument, 0, 'g'},
      { "key-algorithm",  required_argument, 0, 'G'},
      { "name",           required_argument, 0, 'n'},
      { "passin",         required_argument, 0,  0 },
      { "cphash",         required_argument, 0,  1 },
      { "autoflush",      no_argument,       0, 'R' },
    };

    *opts = tpm2_options_new("C:u:r:c:a:p:L:g:G:n:R", ARRAY_LEN(topts), topts,
        on_option, 0, 0);

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
    rc = load_external(ectx);
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

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("loadexternal", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
