/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

typedef struct tpm2_policysigned_ctx tpm2_policysigned_ctx;
struct tpm2_policysigned_ctx {
    const char *session_path;
    tpm2_session *session;

    const char *policy_digest_path;

    TPMT_SIGNATURE signature;
    TPMI_ALG_SIG_SCHEME format;
    TPMI_ALG_HASH halg;
    char *sig_file_path;

    const char *context_arg;
    tpm2_loaded_object key_context_object;

    bool is_nonce_tpm;

    INT32 expiration;

    char *policy_ticket_path;

    char *policy_timeout_path;

    const char *raw_data_path;

    const char *cphash_path;

    const char *policy_qualifier_data;

    union {
        struct {
            UINT8 halg :1;
            UINT8 sig :1;
            UINT8 fmt :1;
        };
        UINT8 all;
    } flags;
};

static tpm2_policysigned_ctx ctx = {
    .signature = {
        .sigAlg = TPM2_ALG_RSASSA,
        .signature.rsassa.hash = TPM2_ALG_SHA256,
    },
    .halg = TPM2_ALG_SHA256
};

static bool on_option(char key, char *value) {

    bool result = true;
    switch (key) {
    case 'L':
        ctx.policy_digest_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Unable to convert algorithm, got: \"%s\"", value);
            return false;
        }
        ctx.flags.halg = 1;
        break;
    case 'f':
        ctx.format = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
        if (ctx.format == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
        ctx.flags.fmt = 1;
        break;
    case 's':
        ctx.sig_file_path = value;
        ctx.flags.sig = 1;
        break;
    case 'c':
        ctx.context_arg = value;
        break;
    case 'q':
        ctx.policy_qualifier_data = value;
        break;
    case 0:
        ctx.policy_ticket_path = value;
        break;
    case 1:
        ctx.policy_timeout_path = value;
        break;
    case 2:
        ctx.raw_data_path = value;
        break;
    case 3:
        ctx.cphash_path = value;
        break;
    case 'x':
        ctx.is_nonce_tpm = true;
        break;
    case 't':
        result = tpm2_util_string_to_int32(value, &ctx.expiration);
        if (!result) {
            LOG_ERR("Failed reading expiration duration from value, got:\"%s\"",
                    value);
            return false;
        }
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy",         required_argument, NULL, 'L' },
        { "session",        required_argument, NULL, 'S' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "signature",      required_argument, NULL, 's' },
        { "format",         required_argument, NULL, 'f' },
        { "key-context",    required_argument, NULL, 'c' },
        { "expiration",     required_argument, NULL, 't' },
        { "qualification",  required_argument, NULL, 'q' },
        { "nonce-tpm",      no_argument,       NULL, 'x' },
        { "ticket",         required_argument, NULL,  0  },
        { "timeout",        required_argument, NULL,  1  },
        { "raw-data",       required_argument, NULL,  2  },
        { "cphash-input",   required_argument, NULL,  3  },
    };

    *opts = tpm2_options_new("L:S:g:s:f:c:t:q:x", ARRAY_LEN(topts), topts, on_option,
    NULL, 0);

    return *opts != NULL;
}

static bool is_input_option_args_valid(void) {

    if (!ctx.context_arg) {
            LOG_ERR("Must specify verifying key context -c.");
            return false;
        }

    if (ctx.raw_data_path) {
        if (ctx.is_nonce_tpm && !ctx.session_path) {
            LOG_ERR("Must specify -S session file.");
            return false;
        }
        return true;
    }

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    return true;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    bool retval = is_input_option_args_valid();
    if (!retval) {
        return tool_rc_option_error;
    }

    if (ctx.flags.sig) {
        tpm2_convert_sig_fmt fmt =
                ctx.flags.fmt ? signature_format_plain : signature_format_tss;
        bool res = tpm2_convert_sig_load(ctx.sig_file_path, fmt, ctx.format,
                ctx.halg, &ctx.signature);
        if (!res) {
            return tool_rc_general_error;
        }
    }

    /*
     * For signature verification only object load is needed, not auth.
     */
    tool_rc tmp_rc = tpm2_util_object_load(ectx, ctx.context_arg,
            &ctx.key_context_object,
            TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }


    tool_rc rc = tpm2_session_restore(ectx, ctx.session_path, false,
            &ctx.session);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPM2B_TIMEOUT *timeout = NULL;
    TPMT_TK_AUTH *policy_ticket = NULL;
    rc = tpm2_policy_build_policysigned(ectx, ctx.session,
        &ctx.key_context_object, &ctx.signature, ctx.expiration, &timeout,
        &policy_ticket, ctx.policy_qualifier_data, ctx.is_nonce_tpm,
        ctx.raw_data_path, ctx.cphash_path);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build policysigned TPM");
        goto tpm2_tool_onrun_out;
    }

    if (ctx.raw_data_path) {
        goto tpm2_tool_onrun_out;
    }

    rc = tpm2_policy_tool_finish(ectx, ctx.session, ctx.policy_digest_path);
    if (rc != tool_rc_success) {
        goto tpm2_tool_onrun_out;
    }

    if (ctx.policy_timeout_path) {
        if(!timeout->size) {
            LOG_WARN("Policy assertion did not produce timeout");
        } else {
            retval = files_save_bytes_to_file(ctx.policy_timeout_path,
            timeout->buffer, timeout->size);
        }
    }
    if (!retval) {
        LOG_ERR("Failed to save timeout to file.");
        rc = tool_rc_general_error;
        goto tpm2_tool_onrun_out;
    }

    if (ctx.policy_ticket_path) {
        if (!policy_ticket->digest.size) {
            LOG_WARN("Policy assertion did not produce auth ticket.");
        } else {
            retval = files_save_authorization_ticket(policy_ticket,
            ctx.policy_ticket_path);
        }
    }
    if (!retval) {
        LOG_ERR("Failed to save auth ticket");
        rc = tool_rc_general_error;
    }

tpm2_tool_onrun_out:
    free(timeout);
    free(policy_ticket);
    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    return tpm2_session_close(&ctx.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("policysigned", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
