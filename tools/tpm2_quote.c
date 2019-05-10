/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <tss2/tss2_esys.h>

#include "tpm2_convert.h"
#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_openssl.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"


typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    struct {
        const char *auth_str;
        tpm2_session *session;
    } ak;
    char *outFilePath;
    char *signature_path;
    char *message_path;
    char *pcr_path;
    FILE *pcr_output;
    tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    tpm2_algorithm algs;
    TPM2B_DATA qualifyingData;
    TPML_PCR_SELECTION pcrSelections;
    TPMS_CAPABILITY_DATA cap_data;
    const char *context_arg;
    tpm2_loaded_object context_object;
    struct {
        UINT8  p : 1;
        UINT8 l : 1;
        UINT8 L : 1;
        UINT8 o : 1;
        UINT8 G : 1;
    } flags;
    tpm2_pcrs pcrs;
};

static tpm_quote_ctx ctx = {
    .algs = {
        .count = 3,
        .alg = {
            TPM2_ALG_SHA1,
            TPM2_ALG_SHA256,
            TPM2_ALG_SHA384
        }
    },
    .qualifyingData = TPM2B_EMPTY_INIT,
};


// write all PCR banks according to g_pcrSelection & g_pcrs->
static bool write_pcr_values() {

    // PCR output to file wasn't requested
    if (ctx.pcr_output == NULL) {
        return true;
    }

    // Export TPML_PCR_SELECTION structure to pcr outfile
    if (fwrite(&ctx.pcrSelections,
            sizeof(TPML_PCR_SELECTION), 1,
            ctx.pcr_output) != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    // Export PCR digests to pcr outfile
    if (fwrite(&ctx.pcrs.count, sizeof(UINT32), 1, ctx.pcr_output) != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    UINT32 j;
    for (j = 0; j < ctx.pcrs.count; j++) {
        if (fwrite(&ctx.pcrs.pcr_values[j], sizeof(TPML_DIGEST), 1, ctx.pcr_output) != 1) {
            LOG_ERR("write to output file failed: %s", strerror(errno));
            return false;
        }
    }

    return true;
}

static bool write_output_files(TPM2B_ATTEST *quoted, TPMT_SIGNATURE *signature) {

    bool res = true;
    if (ctx.signature_path) {
        res &= tpm2_convert_sig_save(signature, ctx.sig_format, ctx.signature_path);
    }

    if (ctx.message_path) {
        res &= files_save_bytes_to_file(ctx.message_path,
                (UINT8*)quoted->attestationData,
                quoted->size);
    }

    res &= write_pcr_values();

    return res;
}

static bool quote(ESYS_CONTEXT *ectx, TPML_PCR_SELECTION *pcrSelection)
{
    TPM2_RC rval;
    TPMT_SIG_SCHEME inScheme;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;

    if(!ctx.flags.G || !get_signature_scheme(ectx, ctx.context_object.tr_handle,
                            ctx.sig_hash_algorithm, TPM2_ALG_NULL, &inScheme)) {
        inScheme.scheme = TPM2_ALG_NULL;
    }

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx,
                            ctx.context_object.tr_handle,
                            ctx.ak.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        return false;
    }

    rval = Esys_Quote(ectx, ctx.context_object.tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &ctx.qualifyingData, &inScheme, pcrSelection,
                &quoted, &signature);
    if(rval != TPM2_RC_SUCCESS)
    {
        LOG_PERR(Esys_Quote, rval);
        return false;
    }

    tpm2_tool_output( "quoted: " );
    tpm2_util_print_tpm2b((TPM2B *)quoted);
    tpm2_tool_output("\nsignature:\n" );
    tpm2_tool_output("  alg: %s\n", tpm2_alg_util_algtostr(signature->sigAlg, tpm2_alg_util_flags_sig));

    UINT16 size;
    BYTE *sig = tpm2_convert_sig(&size, signature);
    tpm2_tool_output("  sig: ");
    tpm2_util_hexdump(sig, size);
    tpm2_tool_output("\n");
    free(sig);

    if (ctx.pcr_output) {
        // Filter out invalid/unavailable PCR selections
        if (!pcr_check_pcr_selection(&ctx.cap_data, &ctx.pcrSelections)) {
            LOG_ERR("Failed to filter unavailable PCR values for quote!");
            return false;
        }

        // Gather PCR values from the TPM (the quote doesn't have them!)
        if (!pcr_read_pcr_values(ectx, &ctx.pcrSelections, &ctx.pcrs)) {
            LOG_ERR("Failed to retrieve PCR values related to quote!");
            return false;
        }

        // Grab the digest from the quote
        TPM2B_DIGEST quoteDigest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
        TPM2B_DATA extraData = TPM2B_TYPE_INIT(TPM2B_DATA, buffer);
        if (!tpm2_util_get_digest_from_quote(quoted, &quoteDigest, &extraData)) {
            LOG_ERR("Failed to get digest from quote!");
            return false;
        }

        // Print out PCR values as output
        if (!pcr_print_pcr_struct(&ctx.pcrSelections, &ctx.pcrs)) {
            LOG_ERR("Failed to print PCR values related to quote!");
            return false;
        }

        // Calculate the digest from our selected PCR values (to ensure correctness)
        TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
        if (!tpm2_openssl_hash_pcr_banks(ctx.sig_hash_algorithm, &ctx.pcrSelections, &ctx.pcrs, &pcr_digest)) {
            LOG_ERR("Failed to hash PCR values related to quote!");
            return false;
        }
        tpm2_tool_output("calcDigest: ");
        tpm2_util_hexdump(pcr_digest.buffer, pcr_digest.size);
        tpm2_tool_output("\n");

        // Make sure digest from quote matches calculated PCR digest
        if (!tpm2_util_verify_digests(&quoteDigest, &pcr_digest)) {
            LOG_ERR("Error validating calculated PCR composite with quote");
            return false;
        }
    }

    // Write everything out
    bool res = write_output_files(quoted, signature);

    free(quoted);
    free(signature);

    return res;
}

static bool on_option(char key, char *value) {

    switch(key)
    {
    case 'C':
        ctx.context_arg = value;
        break;
    case 'P':
        ctx.ak.auth_str = value;
        break;
    case 'l':
        if(!pcr_parse_list(value, strlen(value), &ctx.pcrSelections.pcrSelections[0]))
        {
            LOG_ERR("Could not parse pcr list, got: \"%s\"", value);
            return false;
        }
        ctx.flags.l = 1;
        break;
    case 'L':
        if(!pcr_parse_selections(value, &ctx.pcrSelections))
        {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'o':
        ctx.outFilePath = value;
        ctx.flags.o = 1;
        break;
    case 'q':
        ctx.qualifyingData.size = sizeof(ctx.qualifyingData) - 2;
        if(tpm2_util_hex_to_byte_structure(value, &ctx.qualifyingData.size, ctx.qualifyingData.buffer) != 0)
        {
            LOG_ERR("Could not convert \"%s\" from a hex string to byte array!", value);
            return false;
        }
        break;
    case 's':
         ctx.signature_path = value;
         break;
    case 'm':
         ctx.message_path = value;
         break;
    case 'p':
         ctx.pcr_path = value;
         ctx.flags.p = 1;
         break;
    case 'f':
         ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

         if (ctx.sig_format == signature_format_err) {
            return false;
         }
         break;
    case 'g':
        ctx.sig_hash_algorithm = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if(ctx.sig_hash_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert signature hash algorithm selection, got: \"%s\"", value);
            return false;
        }
        ctx.flags.G = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "ak-context",           required_argument, NULL, 'C' },
        { "auth-ak",              required_argument, NULL, 'P' },
        { "id-list",              required_argument, NULL, 'l' },
        { "sel-list",             required_argument, NULL, 'L' },
        { "qualify-data",         required_argument, NULL, 'q' },
        { "signature",            required_argument, NULL, 's' },
        { "message",              required_argument, NULL, 'm' },
        { "pcrs",                 required_argument, NULL, 'p' },
        { "format",               required_argument, NULL, 'f' },
        { "halg",                 required_argument, NULL, 'g' }
    };

    *opts = tpm2_options_new("C:P:l:L:q:s:m:p:f:g:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    /* TODO this whole file needs to be re-done, especially the option validation */
    if (!ctx.flags.l && !ctx.flags.L) {
        LOG_ERR("Expected either -l or -L to be specified.");
        return -1;
    }

    result = tpm2_auth_util_from_optarg(ectx, ctx.ak.auth_str,
            &ctx.ak.session, false);
    if (!result) {
        LOG_ERR("Invalid AK authorization, got\"%s\"", ctx.ak.auth_str);
        goto out;
    }

    if (ctx.flags.p) {
        if (!ctx.flags.G) {
            LOG_ERR("Must specify -G if -p is requested.");
            return -1;
        }
        ctx.pcr_output = fopen(ctx.pcr_path, "wb+");
        if (!ctx.pcr_output) {
            LOG_ERR("Could not open PCR output file \"%s\" error: \"%s\"",
                    ctx.pcr_path, strerror(errno));
            goto out;
        }
    }

    result = tpm2_util_object_load(ectx, ctx.context_arg,
                                &ctx.context_object);
    if (!result) {
        goto out;
    }

    result = pcr_get_banks(ectx, &ctx.cap_data, &ctx.algs);
    if (!result) {
        goto out;
    }

    result = quote(ectx, &ctx.pcrSelections);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    if (ctx.pcr_output) {
        fclose(ctx.pcr_output);
    }

    result = tpm2_session_close(&ctx.ak.session);
    if (!result) {
        rc = 1;
    }

    return rc;
}
