/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_sign_ctx tpm_sign_ctx;
struct tpm_sign_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } signing_key;

    bool is_input_msg_digest;
    BYTE *msg;
    UINT16 length;
    char *input_file;
    bool is_hash_ticket_specified;
    TPMT_TK_HASHCHECK validation;

    TPMI_ALG_HASH halg;
    TPMI_ALG_SIG_SCHEME sig_scheme;
    TPMT_SIG_SCHEME in_scheme;
    TPM2B_DIGEST *digest;
    tpm2_convert_sig_fmt sig_format;

    char *commit_index;

    /*
     * Outputs
     */
    TPMT_SIGNATURE *signature;
    char *output_path;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_sign_ctx ctx = {
    .halg = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc sign(ESYS_CONTEXT *ectx) {

    return tpm2_sign(ectx, &ctx.signing_key.object, ctx.digest, &ctx.in_scheme,
        &ctx.validation, &ctx.signature, &ctx.cp_hash,
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
    is_file_op_success = tpm2_convert_sig_save(ctx.signature, ctx.sig_format,
        ctx.output_path);
    if (!is_file_op_success) {
        rc = tool_rc_general_error;
    }

    return rc;
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
     * Signing key object loaded in check_options
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * Applicable when input data is not a digest, rather the message to sign.
     * A digest is calculated first in this case.
     */
    tool_rc rc = tool_rc_success;
    TPMT_TK_HASHCHECK *temp_validation_ticket = NULL;
    if (!ctx.is_input_msg_digest) {

        FILE *input = ctx.input_file ? fopen(ctx.input_file, "rb") : stdin;
        if (!input) {
            LOG_ERR("Could not open file \"%s\"", ctx.input_file);
            return tool_rc_general_error;
        }

        rc = tpm2_hash_file(ectx, ctx.halg, TPM2_RH_OWNER, input, &ctx.digest,
                &temp_validation_ticket);
        if (input != stdin) {
            fclose(input);
        }

        if (rc != tool_rc_success) {
            LOG_ERR("Could not hash input");
        } else {
            ctx.validation = *temp_validation_ticket;
        }

        free(temp_validation_ticket);
    }

    if (ctx.is_input_msg_digest) {
        /*
         * else process it as a pre-computed digest
         */
        ctx.digest = malloc(sizeof(TPM2B_DIGEST));
        if (!ctx.digest) {
            LOG_ERR("oom");
            return tool_rc_general_error;
        }

        ctx.digest->size = sizeof(ctx.digest->buffer);
        bool result = files_load_bytes_from_buffer_or_file_or_stdin(0,
                ctx.input_file, &ctx.digest->size, ctx.digest->buffer);
        if (!result) {
            return tool_rc_general_error;
        }

        /*
         * Applicable to un-restricted signing keys
         * NOTE: When digests without tickets are specified for restricted keys,
         * the sign operation will fail.
         */
        if (ctx.is_input_msg_digest && !ctx.is_hash_ticket_specified) {
            ctx.validation.tag = TPM2_ST_HASHCHECK;
            ctx.validation.hierarchy = TPM2_RH_NULL;
            memset(&ctx.validation.digest, 0, sizeof(ctx.validation.digest));
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.signing_key.object.session,
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

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.signing_key.ctx_path,
            ctx.signing_key.auth_str, &ctx.signing_key.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    /*
     * Set signature scheme for key type, or validate chosen scheme is
     * allowed for key type.
     */
    rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.signing_key.object.tr_handle, &ctx.halg, ctx.sig_scheme,
            &ctx.in_scheme);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid signature scheme for key type!");
        return rc;
    }

    if (ctx.in_scheme.scheme != TPM2_ALG_ECDAA && ctx.commit_index) {
        LOG_ERR("Commit counter is only applicable in an ECDAA scheme.");
        return tool_rc_option_error;
    }

    if (ctx.in_scheme.scheme == TPM2_ALG_ECDAA && ctx.commit_index) {
        bool result = tpm2_util_string_to_uint16(ctx.commit_index,
            &ctx.in_scheme.details.ecdaa.count);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    if (ctx.in_scheme.scheme == TPM2_ALG_ECDAA &&
    ctx.sig_format != signature_format_tss) {
        LOG_ERR("Only TSS signature format is possible with ECDAA scheme");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && ctx.output_path) {
        LOG_ERR("Cannot output signature when calculating cpHash");
        return tool_rc_option_error;
    }

    if (!ctx.signing_key.ctx_path) {
        LOG_ERR("Expected option c");
        return tool_rc_option_error;
    }

    if (!ctx.output_path && !ctx.cp_hash_path) {
        LOG_ERR("Expected option o");
        return tool_rc_option_error;
    }

    if (!ctx.is_input_msg_digest && ctx.is_hash_ticket_specified) {
        LOG_WARN("Ignoring the specified validation ticket since no TPM "
                 "calculated digest specified.");
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.signing_key.ctx_path = value;
        break;
    case 'p':
        ctx.signing_key.auth_str = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert to number or lookup algorithm, got: "
                    "\"%s\"", value);
            return false;
        }
        break;
    case 's': {
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
    }
        break;
    case 'd':
        ctx.is_input_msg_digest = true;
        break;
    case 't': {
        bool result = files_load_validation(value, &ctx.validation);
        if (!result) {
            return false;
        }
        ctx.is_hash_ticket_specified = true;
    }
        break;
    case 'o':
        ctx.output_path = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.commit_index = value;
        break;
    case 'f':
        ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
        /* no default */
    }

    return true;
}

static bool on_args(int argc, char *argv[]) {

    if (argc != 1) {
        LOG_ERR("Expected one input file, got: %d", argc);
        return false;
    }

    ctx.input_file = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth",           required_argument, 0, 'p' },
      { "hash-algorithm", required_argument, 0, 'g' },
      { "scheme",         required_argument, 0, 's' },
      { "digest",         no_argument,       0, 'd' },
      { "signature",      required_argument, 0, 'o' },
      { "ticket",         required_argument, 0, 't' },
      { "key-context",    required_argument, 0, 'c' },
      { "format",         required_argument, 0, 'f' },
      { "cphash",         required_argument, 0,  0  },
      { "commit-index",   required_argument, 0,  1  },
    };

    *opts = tpm2_options_new("p:g:dt:o:c:f:s:", ARRAY_LEN(topts), topts,
            on_option, on_args, 0);

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
    rc = sign(ectx);
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
    free(ctx.signature);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.signing_key.object.session);

    /*
     * 3. Close auxiliary sessions
     */
    return rc;
}

static void tpm2_tool_onexit(void) {

    if (ctx.digest) {
        free(ctx.digest);
    }

    free(ctx.msg);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("sign", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, tpm2_tool_onexit)
