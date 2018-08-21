//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include <openssl/rand.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#define BASE_DEFAULT_ATTRS \
    (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT)

#define DEFAULT_NAME_ALG TPM2_ALG_SHA256

typedef struct tpm_loadexternal_ctx tpm_loadexternal_ctx;
struct tpm_loadexternal_ctx {
    char *context_file_path;
    TPMI_RH_HIERARCHY hierarchy_value;
    TPM2_HANDLE handle;
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

static bool load_external(TSS2_SYS_CONTEXT *sapi_context, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv, bool has_priv, TPM2B_NAME *name) {

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_LoadExternal(sapi_context, NULL,
            has_priv ? priv : NULL, pub,
            ctx.hierarchy_value, &ctx.handle, name,
            &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_LoadExternal, rval);
        return false;
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch(key) {
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.hierarchy_value,
                   TPM2_HIERARCHY_FLAGS_ALL);
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
    case 'o':
        ctx.context_file_path = value;
        break;
    case 'A':
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

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",          required_argument, NULL, 'a'},
      { "pubfile",            required_argument, NULL, 'u'},
      { "privfile",           required_argument, NULL, 'r'},
      { "out-context",        required_argument, NULL, 'o'},
      { "object-attributes",  required_argument, NULL, 'A'},
      { "policy-file",        required_argument, NULL, 'L'},
      { "auth-key",           required_argument, NULL, 'p'},
      { "halg",               required_argument, NULL, 'g'},
      { "auth-parent",        required_argument, NULL, 'P'},
      { "key-alg",            required_argument, NULL, 'G'},
      { "name",               required_argument, NULL, 'n'},
      { "passin",             required_argument, NULL,  0 },
    };

    *opts = tpm2_options_new("a:u:r:o:A:p:L:g:G:n:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    bool result;

    if (!ctx.public_key_path && !ctx.private_key_path) {
        LOG_ERR("Expected either -r or -u options");
        return 1;
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
        return 1;
    }

    TPMI_ALG_PUBLIC alg = TPM2_ALG_NULL;

    if (ctx.key_type) {
        alg = tpm2_alg_util_from_optarg(ctx.key_type,
                        tpm2_alg_util_flags_asymmetric
                        |tpm2_alg_util_flags_symmetric);
        if (alg == TPM2_ALG_ERROR) {
            LOG_ERR("Unsupported key type, got: \"%s\"",
                    ctx.key_type);
            return 1;
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
        result = tpm2_attr_util_obj_from_optarg(ctx.attrs,
            &pub.publicArea.objectAttributes);
        if (!result) {
            return 1;
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
        pub.publicArea.authPolicy.size = sizeof(pub.publicArea.authPolicy.buffer);
        bool res = files_load_bytes_from_path(ctx.policy,
                    pub.publicArea.authPolicy.buffer, &pub.publicArea.authPolicy.size);
        if (!res) {
            return false;
        }
    }

    /*
     * Set the name alg, again this gets wipped on a TSS object
     */
    pub.publicArea.nameAlg =
        ctx.name_alg ? tpm2_alg_util_from_optarg(ctx.name_alg, tpm2_alg_util_flags_hash
                |tpm2_alg_util_flags_misc) : DEFAULT_NAME_ALG;
    if (pub.publicArea.nameAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid name hashing algorithm, got: \"%s\"", ctx.name_alg);
        return 1;
    }

    /*
     * Set the AUTH value for sensitive portion
     */
    TPM2B_SENSITIVE priv = {
        .size = 0,
        .sensitiveArea = {
            /* no parent seed value for protection */
            .seedValue = { .size = 0 },
            .authValue = { .size = 0 }
        },
    };

    if (ctx.auth) {
        TPMS_AUTH_COMMAND tmp;
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.auth, &tmp, NULL);
        if (!result) {
            LOG_ERR("Invalid key authorization, got\"%s\"", ctx.auth);
            return 1;
        }

        priv.sensitiveArea.authValue = tmp.hmac;
    }

    tpm2_openssl_load_rc load_status = lprc_error;
    if (ctx.private_key_path) {
        load_status = tpm2_openssl_load_private(ctx.private_key_path, ctx.passin,
                alg, &pub, &priv);
        if (load_status == lprc_error) {
            return 1;
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
        return 1;

    } else if(tpm2_openssl_did_load_public(load_status) && ctx.public_key_path) {
        LOG_WARN("Loaded a public key from the private portion"
                 " and a public portion was specified via -u. Defaulting"
                 " to specified public");

        memset(&pub.publicArea.parameters, 0, sizeof(pub.publicArea.parameters));
        pub.publicArea.type = TPM2_ALG_NULL;
    }

    if (ctx.public_key_path) {
        result = tpm2_openssl_load_public(ctx.public_key_path, alg, &pub);
        if (!result) {
            return 1;
        }
    }

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    result = load_external(sapi_context, &pub, &priv, ctx.private_key_path != NULL, &name);
    if (!result) {
        return 1;
    }

    tpm2_tool_output("handle: 0x%X\n", ctx.handle);
    tpm2_tool_output("name: 0x");
    tpm2_util_hexdump(name.name, name.size);
    tpm2_tool_output("\n");

    if(ctx.context_file_path) {
        result = files_save_tpm_context_to_path_sapi(sapi_context, ctx.handle,
                   ctx.context_file_path);
        if (!result) {
            return 1;
        }
    }

    if (ctx.name_path) {
        result = files_save_bytes_to_file(ctx.name_path, name.name, name.size);
        if(!result) {
            return 1;
        }
    }

    return 0;
}
