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

typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    char *signature_path;
    char *message_path;
    char *pcr_path;
    FILE *pcr_output;
    tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    tpm2_algorithm algs;
    TPM2B_DATA qualification_data;
    TPML_PCR_SELECTION pcr_selections;
    TPMS_CAPABILITY_DATA cap_data;
    tpm2_pcrs pcrs;

    char *cp_hash_path;
};

static tpm_quote_ctx ctx = {
    .sig_hash_algorithm = TPM2_ALG_NULL,
    .qualification_data = TPM2B_EMPTY_INIT,
};


// write all PCR banks according to g_pcrSelection & g_pcrs->
static bool write_pcr_values() {
    UINT32 count;

    // PCR output to file wasn't requested
    if (ctx.pcr_output == NULL) {
        return true;
    }

    // Make sure the file content is written in little endian format
    ctx.pcr_selections.count = htole32(ctx.pcr_selections.count);
    UINT32 i;
    for (i = 0; i < le32toh(ctx.pcr_selections.count); i++)
        ctx.pcr_selections.pcrSelections[i].hash = htole16(ctx.pcr_selections.pcrSelections[i].hash);

    // Export TPML_PCR_SELECTION structure to pcr outfile
    if (fwrite(&ctx.pcr_selections, sizeof(TPML_PCR_SELECTION), 1,
            ctx.pcr_output) != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    count = htole32(ctx.pcrs.count);
    // Export PCR digests to pcr outfile
    if (fwrite(&count, sizeof(UINT32), 1, ctx.pcr_output) != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    UINT32 j;
    for (j = 0; j < ctx.pcrs.count; j++) {
        ctx.pcrs.pcr_values[j].count = htole32(ctx.pcrs.pcr_values[j].count);

        UINT32 k;
        for(k = 0; k < le32toh(ctx.pcrs.pcr_values[j].count); k++)
            ctx.pcrs.pcr_values[j].digests[k].size = htole16(ctx.pcrs.pcr_values[j].digests[k].size);

        if (fwrite(&ctx.pcrs.pcr_values[j], sizeof(TPML_DIGEST), 1,
                ctx.pcr_output) != 1) {
            LOG_ERR("write to output file failed: %s", strerror(errno));
            return false;
        }
    }

    return true;
}

static bool write_output_files(TPM2B_ATTEST *quoted, TPMT_SIGNATURE *signature) {

    bool res = true;
    if (ctx.signature_path) {
        res &= tpm2_convert_sig_save(signature, ctx.sig_format,
                ctx.signature_path);
    }

    if (ctx.message_path) {
        res &= files_save_bytes_to_file(ctx.message_path,
                (UINT8*) quoted->attestationData, quoted->size);
    }

    res &= write_pcr_values();

    return res;
}

static tool_rc quote(ESYS_CONTEXT *ectx, TPML_PCR_SELECTION *pcr_selection) {

    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;
    TPMT_SIG_SCHEME in_scheme = { .scheme = TPM2_ALG_NULL };

    tool_rc rc = tpm2_alg_util_get_signature_scheme(ectx,
            ctx.key.object.tr_handle, &ctx.sig_hash_algorithm, TPM2_ALG_NULL,
            &in_scheme);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        rc = tpm2_quote(ectx, &ctx.key.object, &in_scheme,
        &ctx.qualification_data, pcr_selection, &quoted, &signature, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }

        return rc;
    }

    rc = tpm2_quote(ectx, &ctx.key.object, &in_scheme, &ctx.qualification_data,
            pcr_selection, &quoted, &signature, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_tool_output("quoted: ");
    tpm2_util_print_tpm2b(quoted);
    tpm2_tool_output("\nsignature:\n");
    tpm2_tool_output("  alg: %s\n",
            tpm2_alg_util_algtostr(signature->sigAlg, tpm2_alg_util_flags_sig));

    UINT16 size;
    BYTE *sig = tpm2_convert_sig(&size, signature);
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
        rc = pcr_read_pcr_values(ectx, &ctx.pcr_selections, &ctx.pcrs);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to retrieve PCR values related to quote!");
            return rc;
        }

        // Grab the digest from the quote
        TPMS_ATTEST attest;
        rc = files_tpm2b_attest_to_tpms_attest(quoted, &attest);
        if (rc != tool_rc_success) {
            return rc;
        }

        // Print out PCR values as output
        if (!pcr_print_pcr_struct(&ctx.pcr_selections, &ctx.pcrs)) {
            LOG_ERR("Failed to print PCR values related to quote!");
            return tool_rc_general_error;
        }

        // Calculate the digest from our selected PCR values (to ensure correctness)
        TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
        if (!tpm2_openssl_hash_pcr_banks(ctx.sig_hash_algorithm,
                &ctx.pcr_selections, &ctx.pcrs, &pcr_digest)) {
            LOG_ERR("Failed to hash PCR values related to quote!");
            return tool_rc_general_error;
        }
        tpm2_tool_output("calcDigest: ");
        tpm2_util_hexdump(pcr_digest.buffer, pcr_digest.size);
        tpm2_tool_output("\n");

        // Make sure digest from quote matches calculated PCR digest
        if (!tpm2_util_verify_digests(&attest.attested.quote.pcrDigest, &pcr_digest)) {
            LOG_ERR("Error validating calculated PCR composite with quote");
            return tool_rc_general_error;
        }
    }

    // Write everything out
    bool res = write_output_files(quoted, signature);

    free(quoted);
    free(signature);

    return res ? tool_rc_success : tool_rc_general_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
        break;
    case 'l':
        if (!pcr_parse_selections(value, &ctx.pcr_selections)) {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        break;
    case 'q':
        ctx.qualification_data.size = sizeof(ctx.qualification_data.buffer);
        return tpm2_util_bin_from_hex_or_file(value, &ctx.qualification_data.size,
                ctx.qualification_data.buffer);
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
            LOG_ERR(
                    "Could not convert signature hash algorithm selection, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "key-context",    required_argument, NULL, 'c' },
        { "auth",           required_argument, NULL, 'p' },
        { "pcr-list",       required_argument, NULL, 'l' },
        { "qualification",  required_argument, NULL, 'q' },
        { "signature",      required_argument, NULL, 's' },
        { "message",        required_argument, NULL, 'm' },
        { "pcr",            required_argument, NULL, 'o' },
        { "format",         required_argument, NULL, 'f' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "cphash",         required_argument, NULL,  0  }
    };

    *opts = tpm2_options_new("c:p:l:q:s:m:o:f:g:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /* TODO this whole file needs to be re-done, especially the option validation */
    if (!ctx.pcr_selections.count) {
        LOG_ERR("Expected -l to be specified.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && (ctx.signature_path || ctx.message_path)) {
        LOG_ERR("Cannot produce output when calculating cpHash");
        return tool_rc_option_error;
    }

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
            ctx.key.auth_str, &ctx.key.object, false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    if (ctx.pcr_path) {
        ctx.pcr_output = fopen(ctx.pcr_path, "wb+");
        if (!ctx.pcr_output) {
            LOG_ERR("Could not open PCR output file \"%s\" error: \"%s\"",
                    ctx.pcr_path, strerror(errno));
            return tool_rc_general_error;
        }
    }

    rc = pcr_get_banks(ectx, &ctx.cap_data, &ctx.algs);
    if (rc != tool_rc_success) {
        return rc;
    }

    return quote(ectx, &ctx.pcr_selections);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    if (ctx.pcr_output) {
        fclose(ctx.pcr_output);
    }
    return tpm2_session_close(&ctx.key.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("quote", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
