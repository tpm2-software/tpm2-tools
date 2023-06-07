/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"
#include "tpm2_systemdeps.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    TPM2B_DATA qualification_data;
    TPML_PCR_SELECTION pcr_selections;
    TPMS_CAPABILITY_DATA cap_data;
    tpm2_pcrs pcrs;
    tpm2_convert_pcrs_output_fmt pcrs_format;
    TPMT_SIG_SCHEME in_scheme;
    TPMI_ALG_SIG_SCHEME sig_scheme;

    /*
     * Outputs
     */
    FILE *pcr_output;
    char *pcr_path;
    char *signature_path;
    char *message_path;
    TPMS_ATTEST attest;
    TPM2B_ATTEST *quoted;
    TPMT_SIGNATURE *signature;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_quote_ctx ctx = {
    .sig_hash_algorithm = TPM2_ALG_NULL,
    .qualification_data = TPM2B_EMPTY_INIT,
    .pcrs_format = pcrs_output_format_serialized,
    .in_scheme.scheme = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc quote(ESYS_CONTEXT *ectx) {

    return tpm2_quote(ectx, &ctx.key.object, &ctx.in_scheme,
        &ctx.qualification_data, &ctx.pcr_selections, &ctx.quoted,
        &ctx.signature, &ctx.cp_hash, ctx.parameter_hash_algorithm);
}

static tool_rc write_output_files(void) {

    bool is_file_op_success = true;
    bool result = true;
    if (ctx.signature_path) {
        result = tpm2_convert_sig_save(ctx.signature, ctx.sig_format,
            ctx.signature_path);
        if (!result) {
            is_file_op_success = result;
        }
    }

    if (ctx.message_path) {
        result = files_save_bytes_to_file(ctx.message_path,
            (UINT8*) &ctx.quoted->attestationData, ctx.quoted->size);
        if (!result) {
            is_file_op_success = result;
        }
    }

    if (ctx.pcr_output) {
        if (ctx.pcrs_format == pcrs_output_format_serialized) {
            result = pcr_fwrite_serialized(&ctx.pcr_selections, &ctx.pcrs,
                ctx.pcr_output);
            if (!result) {
                is_file_op_success = result;
            }
        } else if (ctx.pcrs_format == pcrs_output_format_values) {
            result = pcr_fwrite_values(&ctx.pcr_selections, &ctx.pcrs,
                ctx.pcr_output);
            if (!result) {
                is_file_op_success = result;
            }
        }
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
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
    tpm2_tool_output("quoted: ");
    tpm2_util_print_tpm2b(ctx.quoted);
    tpm2_tool_output("\nsignature:\n");
    tpm2_tool_output("  alg: %s\n", tpm2_alg_util_algtostr(
        ctx.signature->sigAlg, tpm2_alg_util_flags_sig));

    UINT16 size;
    BYTE *sig = tpm2_convert_sig(&size, ctx.signature);
    if (!sig) {
        return tool_rc_general_error;
    }
    tpm2_tool_output("  sig: ");
    tpm2_util_hexdump(sig, size);
    tpm2_tool_output("\n");
    free(sig);

    if (ctx.pcr_output) {
        // Filter out invalid/unavailable PCR selections
        if (!pcr_check_pcr_selection(&ctx.cap_data, &ctx.pcr_selections)) {
            LOG_ERR("Failed to filter unavailable PCR values for quote!");
            return tool_rc_general_error;
        }

        // Gather PCR values from the TPM (the quote doesn't have them!)
        rc = pcr_read_pcr_values(ectx, &ctx.pcr_selections, &ctx.pcrs,
            NULL, TPM2_ALG_ERROR);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to retrieve PCR values related to quote!");
            return rc;
        }

        // Grab the digest from the quote
        rc = files_tpm2b_attest_to_tpms_attest(ctx.quoted, &ctx.attest);
        if (rc != tool_rc_success) {
            return rc;
        }

        // Print out PCR values as output
        bool is_pcr_print_successful = pcr_print_pcr_struct(&ctx.pcr_selections,
            &ctx.pcrs);
        if (!is_pcr_print_successful) {
            LOG_ERR("Failed to print PCR values related to quote!");
            return tool_rc_general_error;
        }

        // Calculate the digest from our selected PCR values (to ensure correctness)
        TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
        bool is_pcr_hashing_success = tpm2_openssl_hash_pcr_banks(
            ctx.sig_hash_algorithm, &ctx.pcr_selections, &ctx.pcrs,
            &pcr_digest);
        if (!is_pcr_hashing_success) {
            LOG_ERR("Failed to hash PCR values related to quote!");
            return tool_rc_general_error;
        }
        tpm2_tool_output("calcDigest: ");
        tpm2_util_hexdump(pcr_digest.buffer, pcr_digest.size);
        tpm2_tool_output("\n");

        // Make sure digest from quote matches calculated PCR digest
        bool is_pcr_digests_equal = tpm2_util_verify_digests(
            &ctx.attest.attested.quote.pcrDigest, &pcr_digest);
        if (!is_pcr_digests_equal) {
            LOG_ERR("Error validating calculated PCR composite with quote");
            return tool_rc_general_error;
        }
    }

    // Write everything out
    return write_output_files();
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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
            ctx.key.auth_str, &ctx.key.object, false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    if (ctx.pcr_path) {
        ctx.pcr_output = fopen(ctx.pcr_path, "wb+");
        if (!ctx.pcr_output) {
            LOG_ERR("Could not open PCR output file \"%s\" error: \"%s\"",
                    ctx.pcr_path, strerror(errno));
            return tool_rc_general_error;
        }
    }

    tpm2_algorithm algs;
    rc = pcr_get_banks(ectx, &ctx.cap_data, &algs);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_alg_util_get_signature_scheme(ectx, ctx.key.object.tr_handle,
        &ctx.sig_hash_algorithm, ctx.sig_scheme, &ctx.in_scheme);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.key.object.session,
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

    /* TODO this whole file needs to be re-done, especially the option validation */
    if (!ctx.pcr_selections.count) {
        LOG_ERR("Expected -l to be specified.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && (ctx.signature_path || ctx.message_path)) {
        LOG_ERR("Cannot produce output when calculating cpHash");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    bool result = true;
    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
        break;
    case 'l':
        result = pcr_parse_selections(value, &ctx.pcr_selections, NULL);
        if (!result) {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        break;
    case 'q':
        ctx.qualification_data.size = sizeof(ctx.qualification_data.buffer);
        return tpm2_util_bin_from_hex_or_file(value,
            &ctx.qualification_data.size, ctx.qualification_data.buffer);
        break;
    case 's':
        ctx.signature_path = value;
        break;
    case 'm':
        ctx.message_path = value;
        break;
    case 'o':
        ctx.pcr_path = value;
        break;
    case 'F':
        ctx.pcrs_format = tpm2_convert_pcrs_output_fmt_from_optarg(value);
        if (ctx.pcrs_format == pcrs_output_format_err) {
            return false;
        }
        break;
    case 'f':
        ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_format == signature_format_err) {
            return false;
        }
        break;
    case 'g':
        ctx.sig_hash_algorithm = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_hash);
        if (ctx.sig_hash_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert signature hash algorithm selection, "
                    "got: \"%s\"", value);
            return false;
        }
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.sig_scheme = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_sig);
        if (ctx.sig_scheme == TPM2_ALG_ERROR) {
            LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
            return false;
        }
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "key-context",    required_argument, 0, 'c' },
        { "auth",           required_argument, 0, 'p' },
        { "pcr-list",       required_argument, 0, 'l' },
        { "qualification",  required_argument, 0, 'q' },
        { "signature",      required_argument, 0, 's' },
        { "message",        required_argument, 0, 'm' },
        { "pcr",            required_argument, 0, 'o' },
        { "pcrs_format",    required_argument, 0, 'F' },
        { "format",         required_argument, 0, 'f' },
        { "hash-algorithm", required_argument, 0, 'g' },
        { "cphash",         required_argument, 0,  0  },
        { "scheme",         required_argument, 0,  1  },
    };

    *opts = tpm2_options_new("c:p:l:q:s:m:o:F:f:g:", ARRAY_LEN(topts), topts,
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
    rc = quote(ectx);
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
    if (ctx.pcr_output) {
        fclose(ctx.pcr_output);
    }

    free(ctx.quoted);
    free(ctx.signature);

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tpm2_session_close(&ctx.key.object.session);

    /*
     * 3. Close auxiliary sessions
     */

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("quote", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
