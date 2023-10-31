/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_systemdeps.h"
#include "tpm2_tool.h"
#include "tpm2_eventlog.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    union {
        struct {
            UINT8 msg :1;
            UINT8 sig :1;
            UINT8 pcr :1;
            UINT8 hlg :1;
            UINT8 eventlog :1;
        };
        UINT8 all;
    } flags;
    TPMI_ALG_HASH halg;
    TPM2B_DIGEST msg_hash;
    TPM2B_DIGEST pcr_hash;
    TPMS_ATTEST attest;
    TPM2B_DATA extra_data;
    TPM2B_MAX_BUFFER signature;
    char *msg_file_path;
    char *sig_file_path;
    char *out_file_path;
    char *pcr_file_path;
    const char *pubkey_file_path;
    char *eventlog_path;
    tpm2_loaded_object key_context_object;
    const char *pcr_selection_string;
};

static tpm2_verifysig_ctx ctx = {
        .halg = TPM2_ALG_SHA256,
        .msg_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
        .pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

/**
 * Size of the table with the possible padding schemes
 */
#define N_PADDING 3

/**
 * Table with possible padding schemes to guess the one appropriate for
 * for RSA signature verification
 */
static const int rsaPadding[N_PADDING] = { -1 , /*<< no padding */
                                           RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING };

static bool compare_pcr_selection(TPML_PCR_SELECTION *attest_sel, TPML_PCR_SELECTION *pcr_sel) {
    if (attest_sel->count != pcr_sel->count) {
        LOG_ERR("Selection sizes do not match.");
        return false;
    }
    for (uint32_t i = 0; i < attest_sel->count; i++) {
        for (uint32_t j = 0; j < pcr_sel->count; j++) {
            if (attest_sel->pcrSelections[i].hash ==
                pcr_sel->pcrSelections[j].hash) {
                if (attest_sel->pcrSelections[i].sizeofSelect !=
                        pcr_sel->pcrSelections[j].sizeofSelect) {
                    LOG_ERR("Bitmask size does not match");
                    return false;
                }
                if (memcmp(&attest_sel->pcrSelections[i].pcrSelect[0],
                           &pcr_sel->pcrSelections[j].pcrSelect[0],
                           attest_sel->pcrSelections[i].sizeofSelect) != 0) {
                    LOG_ERR("Selection bitmasks do not match");
                    return false;
                }
                break;
            }
            if (j == pcr_sel->count - 1) {
                LOG_ERR("Hash selections to not match.");
                return false;
            }
        }
    }
    return true;
}

static bool verify(void) {

    bool result = false;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int rc;

    /* read the public key */
    EVP_PKEY *pkey = NULL;
    bool ret = tpm2_public_load_pkey(ctx.pubkey_file_path, &pkey);
    if (!ret) {
        return false;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101003L
#if OPENSSL_VERSION_MAJOR < 3
    if (ctx.halg == TPM2_ALG_SM3_256) {
        ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
        if (!ret) {
            LOG_ERR("EVP_PKEY_set_alias_type failed: %s", ERR_error_string(ERR_get_error(), NULL));
            goto err;
        }
    }
#endif
#endif

    /* TODO dump actual signature */
    tpm2_tool_output("sig: ");
    tpm2_util_hexdump(ctx.signature.buffer, ctx.signature.size);
    tpm2_tool_output("\n");

    /* Try all possible padding schemes for verification */
    for (int i = 0; i < N_PADDING; i++) {
        pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkey_ctx) {
            LOG_ERR("EVP_PKEY_CTX_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
            goto err;
        }

        /* get the digest alg */
        /* TODO SPlit loading on plain vs tss format to detect the hash alg */
        /* If its a plain sig we need -g */
        const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(ctx.halg);
        if (!md) {
            LOG_ERR("Algorithm not supported: %x", ctx.halg);
            goto err;
        }

        rc = EVP_PKEY_verify_init(pkey_ctx);
        if (!rc) {
            LOG_ERR("EVP_PKEY_verify_init failed: %s", ERR_error_string(ERR_get_error(), NULL));
            goto err;
        }

        rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
        if (!rc) {
            LOG_ERR("EVP_PKEY_CTX_set_signature_md failed: %s", ERR_error_string(ERR_get_error(), NULL));
            goto err;
        }

        if (rsaPadding[i] != -1) {
            rc = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, rsaPadding[i]);
            if (rc < 0) {
                 LOG_ERR("EVP_PKEY_CTX_set_rsa_padding");
                 goto err;
            }
        }

        // Verify the signature matches message digest

        rc = EVP_PKEY_verify(pkey_ctx, ctx.signature.buffer, ctx.signature.size,
                             ctx.msg_hash.buffer, ctx.msg_hash.size);

        if (rc == 1) {
            break;
        } else {
            EVP_PKEY_CTX_free(pkey_ctx);
            pkey_ctx = NULL;
        }
    }
    if (rc != 1) {
        if (rc == 0) {
            LOG_ERR("Error validating signed message with public key provided");
        } else {
            LOG_ERR("Error %s", ERR_error_string(ERR_get_error(), NULL));
        }
        goto err;
    }

    // Ensure nonce is the same as given
    if (ctx.attest.extraData.size != ctx.extra_data.size ||
        memcmp(ctx.attest.extraData.buffer, ctx.extra_data.buffer,
        ctx.extra_data.size) != 0) {
        LOG_ERR("Error validating nonce from quote");
        goto err;
    }

    // check magic
    if (ctx.attest.magic != TPM2_GENERATED_VALUE) {
        LOG_ERR("Bad magic, got: 0x%x, expected: 0x%x",
                ctx.attest.magic, TPM2_GENERATED_VALUE);
        return false;
    }

    // Also ensure digest from quote matches PCR digest
    if (ctx.flags.pcr) {
        if (!tpm2_util_verify_digests(&ctx.attest.attested.quote.pcrDigest,
                &ctx.pcr_hash)) {
            LOG_ERR("Error validating PCR composite against signed message");
            goto err;
        }
    }

    result = true;

err:

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);

    return result;
}

static TPM2B_ATTEST *message_from_file(const char *msg_file_path) {

    unsigned long size;

    bool result = files_get_file_size_path(msg_file_path, &size);
    if (!result) {
        return NULL;
    }

    if (!size) {
        LOG_ERR("The msg file \"%s\" is empty", msg_file_path);
        return NULL;
    }

    TPM2B_ATTEST *msg = (TPM2B_ATTEST *) calloc(1, sizeof(TPM2B_ATTEST) + size);
    if (!msg) {
        LOG_ERR("OOM");
        return NULL;
    }

    UINT16 tmp = msg->size = size;
    if (!files_load_bytes_from_path(msg_file_path, msg->attestationData,
            &tmp)) {
        free(msg);
        return NULL;
    }
    return msg;
}

static bool parse_selection_data_from_selection_string(FILE *pcr_input,
    TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs) {

    bool result = pcr_parse_selections(ctx.pcr_selection_string, pcr_select,
                                       NULL);
    if (!result) {
        LOG_ERR("Could not parse PCR selections");
        return false;
    }

    /*
     * A tpm2_pcrs->pcr_values[tpm2_pcrs->count] is a TPML_DIGEST structure
     * which can hold a maximum of 8 digests. Once the count of 8 is exhausted
     * we need a new TPML_DIGEST structure.
     *
     * The digests count in a list is tracked with
     * tpm2_pcrs->pcr_values[tpm2_pcrs->count].count
     *
     * A total of such lists is tracked by the tpm2_pcrs->count.
     */
    unsigned i = 0;
    unsigned j = 0;
    unsigned read_size = 0;
    size_t read_count = 0;
    unsigned digest_list_count = 0;
    memset(pcrs, 0, sizeof(tpm2_pcrs));
    /*
     * Iterate through all the PCR banks selected.
     */
    for (i = 0; i < pcr_select->count; i++) {
        /*
         * Ensure all the digests across banks can fit in tpm2_pcrs.
         */
        if (digest_list_count >= TPM2_MAX_PCRS - 1) {
            LOG_ERR("Maximum count for allowed digest lists reached.");
            return false;
        }

        /*
         * Digest size of PCR bank selected in this iteration.
         */
        read_size = tpm2_alg_util_get_hash_size(pcr_select->pcrSelections[i].hash);

        /*
         * Iterate through pcrSelect bytes to find selected PCR index bitmap.
         */
        for (j = 0; j < pcr_select->pcrSelections[i].sizeofSelect * 8; j++) {
            /*
             * Test if PCR index select is true.
             */
            if ((pcr_select->pcrSelections[i].pcrSelect[j / 8] & 1 << (j % 8))
            != 0) {
                /*
                 * Read the digest at a selected PCR index.
                 */
                pcrs->pcr_values[digest_list_count].digests[pcrs->pcr_values[
                    digest_list_count].count].size = read_size;
                read_count = fread(pcrs->pcr_values[digest_list_count].digests[
                    pcrs->pcr_values[digest_list_count].count].buffer,
                    read_size, 1, pcr_input);
                if (read_count != 1) {
                    LOG_ERR("Failed to read PCR digests from file");
                    return false;
                }
                /*
                 * Ensure we don't overrun the allowed digest count in a
                 * TPML_DIGEST.
                 */
                if (pcrs->pcr_values[digest_list_count].count == 7) {
                    digest_list_count++;
                } else {
                    /*
                     * Ensure we populate the digest in a new list if we
                     * exhausted the digest count in the current TPML_DIGEST
                     * instance.
                     */
                    pcrs->pcr_values[digest_list_count].count++;
                }
            }
        }
    }
    /*
     * Update the count of total TPML_DIGEST consumed to accomodate all the
     * selected PCR indices across all the banks.
     */
    pcrs->count = digest_list_count + 1;

    return true;
}

static bool parse_selection_data_from_file(FILE *pcr_input,
    TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs) {

    // Import TPML_PCR_SELECTION structure to pcr outfile
    if (fread(pcr_select, sizeof(TPML_PCR_SELECTION), 1, pcr_input) != 1) {
        LOG_ERR("Failed to read PCR selection from file");
        return false;
    }

    // Import PCR digests to pcr outfile
    if (fread(&pcrs->count, sizeof(UINT32), 1, pcr_input) != 1) {
        LOG_ERR("Failed to read PCR digests header from file");
        return false;
    }

    if (le64toh(pcrs->count) > ARRAY_LEN(pcrs->pcr_values)) {
        LOG_ERR("Malformed PCR file, pcr count cannot be greater than %zu, got: %" PRIu64 " ",
                ARRAY_LEN(pcrs->pcr_values), le64toh((UINT64)pcrs->count));
        return false;
    }

    size_t j;
    for (j = 0; j < le64toh(pcrs->count); j++) {
        if (fread(&pcrs->pcr_values[j], sizeof(TPML_DIGEST), 1, pcr_input)
                != 1) {
            LOG_ERR("Failed to read PCR digest from file");
            return false;
        }
    }

    return true;
}

static bool pcrs_from_file(const char *pcr_file_path,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs) {

    bool result = false;
    unsigned long size;

    if (!files_get_file_size_path(pcr_file_path, &size)) {
        return false;
    }

    if (!size) {
        LOG_ERR("The pcr file \"%s\" is empty", pcr_file_path);
        return false;
    }

    FILE *pcr_input = fopen(pcr_file_path, "rb");
    if (!pcr_input) {
        LOG_ERR("Could not open PCRs input file \"%s\" error: \"%s\"",
                pcr_file_path, strerror(errno));
        goto out;
    }

    if (!ctx.pcr_selection_string) {
        result = parse_selection_data_from_file(pcr_input, pcr_select, pcrs);
        if (!result) {
            goto out;
        }
    } else {
        result = parse_selection_data_from_selection_string(pcr_input,
            pcr_select, pcrs);
        if (!result) {
            goto out;
        }
    }

    result = true;
out:
    if (pcr_input) {
        fclose(pcr_input);
    }

    return result;
}

static bool eventlog_from_file(tpm2_eventlog_context *evctx, const char *file_path) {

    unsigned long size;

    if (!files_get_file_size_path(file_path, &size)) {
        return false;
    }

    if (!size) {
        LOG_ERR("The eventlog file \"%s\" is empty", file_path);
        return false;
    }

    uint8_t *eventlog = calloc(1, size);
    if (!eventlog) {
        LOG_ERR("OOM");
        return false;
    }

    uint16_t size_tmp = size;
    if (!files_load_bytes_from_path(file_path, eventlog, &size_tmp)) {
        free(eventlog);
        return false;
    }

    bool rc = parse_eventlog(evctx, eventlog, size);
    free(eventlog);

    return rc;
}

static tool_rc init(void) {

    /* check flags for mismatches */
    if (!(ctx.pubkey_file_path && ctx.flags.sig && ctx.flags.msg)) {
        LOG_ERR(
                "--pubkey (-u), --msg (-m) and --sig (-s) are required");
        return tool_rc_option_error;
    }
    if (ctx.flags.eventlog && !ctx.flags.pcr) {
        LOG_ERR("PCR file is required to validate eventlog");
        return tool_rc_option_error;
    }

    TPM2B_ATTEST *msg = NULL;
    TPML_PCR_SELECTION pcr_select = { 0 };
    tpm2_pcrs *pcrs;
    tpm2_pcrs temp_pcrs = {};
    tool_rc return_value = tool_rc_general_error;

    msg = message_from_file(ctx.msg_file_path);
    if (!msg) {
        /* message_from_file() logs specific error no need to here */
        return tool_rc_general_error;
    }

    /*
     * If the caller specifies the signature format, like rsassa, that means
     * the caller doesn't have the TPMT signature, but rather a plain signature,
     * and we need to trust what was set in -g as the hash algorithm. The
     * verification will fail.
     *
     * In the case of the TSS signature format, we have the hash alg, so if the user
     * specifies the hash alg, or we're guessing, we should use the right one.
     */
    TPMI_ALG_HASH expected_halg = TPM2_ALG_ERROR;
    bool res = tpm2_convert_sig_load_plain(ctx.sig_file_path,
            &ctx.signature, &expected_halg);
    if (!res) {
        goto err;
    }

    if (expected_halg != TPM2_ALG_NULL) {
        if (ctx.halg != expected_halg) {
            if (ctx.flags.hlg) {
                const char *got_str = tpm2_alg_util_algtostr(ctx.halg, tpm2_alg_util_flags_any);
                const char *expected_str = tpm2_alg_util_algtostr(expected_halg, tpm2_alg_util_flags_any);
                LOG_WARN("User specified hash algorithm of \"%s\", does not match"
                        "expected hash algorithm of \"%s\", using: \"%s\"",
                        got_str, expected_str, expected_str);
            }
            ctx.halg = expected_halg;
        }
    }

    /* If no digest is specified, compute it */
    if (!ctx.flags.msg) {
        /*
         * This is a redundant check since main() checks this case, but we'll add it here to silence any
         * complainers.
         */
        LOG_ERR("No digest set and no message file to compute from, cannot "
                "compute message hash!");
        goto err;
    }

    if (ctx.flags.pcr) {
        if (pcrs_from_file(ctx.pcr_file_path, &pcr_select, &temp_pcrs)) {
            /* pcrs_from_file() logs specific error no need to here */
            pcrs = &temp_pcrs;
        } else {
            goto err;
        }

        if (le32toh(pcr_select.count) > TPM2_NUM_PCR_BANKS)
            goto err;

        UINT32 i;
        for (i = 0; i < le32toh(pcr_select.count); i++)
            if (le16toh(pcr_select.pcrSelections[i].hash) == TPM2_ALG_ERROR)
            goto err;

        if (!tpm2_openssl_hash_pcr_banks_le(ctx.halg, &pcr_select, pcrs,
                &ctx.pcr_hash)) {
            LOG_ERR("Failed to hash PCR values related to quote!");
            goto err;
        }
        if (!pcr_print_pcr_struct_le(&pcr_select, pcrs)) {
            LOG_ERR("Failed to print PCR values related to quote!");
            goto err;
        }
    }

    if (ctx.flags.eventlog && ctx.flags.pcr) {
        if (pcrs_from_file(ctx.pcr_file_path, &pcr_select, &temp_pcrs)) {
            /* pcrs_from_file() logs specific error no need to here */
            pcrs = &temp_pcrs;
        } else {
            goto err;
        }

        if (pcr_select.count > TPM2_NUM_PCR_BANKS)
            goto err;

        tpm2_eventlog_context eventlog_ctx = { 0 };
        bool rc = eventlog_from_file(&eventlog_ctx, ctx.eventlog_path);
        if (!rc) {
            LOG_ERR("Failed to process eventlog");
            goto err;
        }

        bool eventlog_fail = false;
        unsigned vi = 0;
        unsigned di = 0;
        for (unsigned i = 0; i < pcr_select.count; i++) {
            const TPMS_PCR_SELECTION *const sel = &pcr_select.pcrSelections[i];

            // Loop through all PCRs in this bank
            const unsigned bank_size = sel->sizeofSelect * 8;
            for (unsigned pcr_id = 0; pcr_id < bank_size; pcr_id++) {
                // skip non-selected banks
                if (!tpm2_util_is_pcr_select_bit_set(sel, pcr_id)) {
                    continue;
                }
                if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count) {
                    LOG_ERR("Something wrong, trying to print but nothing more");
                    eventlog_fail = true;
                    break;
                }

                // Compare this digest to the computed value from the eventlog
                const TPM2B_DIGEST *pcr = &pcrs->pcr_values[vi].digests[di];
                const uint8_t *pcr_q = pcr->buffer;
                const uint8_t *pcr_e = NULL;

                if (sel->hash == TPM2_ALG_SHA1 && pcr->size == TPM2_SHA1_DIGEST_SIZE) {
                    pcr_e = eventlog_ctx.sha1_pcrs[pcr_id];
                } else if (sel->hash == TPM2_ALG_SHA256 && pcr->size == TPM2_SHA256_DIGEST_SIZE) {
                    pcr_e = eventlog_ctx.sha256_pcrs[pcr_id];
                } else if (sel->hash == TPM2_ALG_SHA384 && pcr->size == TPM2_SHA384_DIGEST_SIZE) {
                    pcr_e = eventlog_ctx.sha384_pcrs[pcr_id];
                } else if (sel->hash == TPM2_ALG_SHA512 && pcr->size == TPM2_SHA512_DIGEST_SIZE) {
                    pcr_e = eventlog_ctx.sha512_pcrs[pcr_id];
                } else if (sel->hash == TPM2_ALG_SM3_256 && pcr->size == TPM2_SM3_256_DIGEST_SIZE) {
                    pcr_e = eventlog_ctx.sm3_256_pcrs[pcr_id];
                } else {
                    LOG_WARN("PCR%u unsupported algorithm/size %u/%u", pcr_id, sel->hash, pcr->size);
                    eventlog_fail = 1;
                }

                if (pcr_e && memcmp(pcr_e, pcr_q, pcr->size) != 0) {
                    LOG_WARN("PCR%u mismatch", pcr_id);
                    eventlog_fail = 1;
                }

                if (++di < pcrs->pcr_values[vi].count) {
                    continue;
                }

                di = 0;
                if (++vi < pcrs->count) {
                    continue;
                }
            }
        }

        if (eventlog_fail) {
            LOG_ERR("Eventlog and quote PCR mismatch");
            goto err;
        }
    }

    tool_rc tmp_rc = files_tpm2b_attest_to_tpms_attest(msg, &ctx.attest);
    if (tmp_rc != tool_rc_success) {
        return_value = tmp_rc;
        goto err;
    }

    if (ctx.flags.pcr) {
        if (!compare_pcr_selection(&ctx.attest.attested.quote.pcrSelect,
                                   &pcr_select)) {
            LOG_ERR("PCR selection does not match PCR slection from attest!");
            goto err;
        }
    }

    // Figure out the digest for this message
    res = tpm2_openssl_hash_compute_data(ctx.halg, msg->attestationData,
            msg->size, &ctx.msg_hash);
    if (!res) {
        LOG_ERR("Compute message hash failed!");
        goto err;
    }

    return_value = tool_rc_success;

err:
    free(msg);

    return return_value;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'u':
        ctx.pubkey_file_path = value;
        break;
    case 'g': {
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Unable to convert algorithm, got: \"%s\"", value);
            return false;
        }
        ctx.flags.hlg = 1;
    }
        break;
    case 'm': {
        ctx.msg_file_path = value;
        ctx.flags.msg = 1;
    }
        break;
    case 'F':
        LOG_WARN("DEPRECATED: Format ignored");
        break;
    case 'q':
        ctx.extra_data.size = sizeof(ctx.extra_data.buffer);
        return tpm2_util_bin_from_hex_or_file(value, &ctx.extra_data.size,
                ctx.extra_data.buffer);
        break;
    case 's':
        ctx.sig_file_path = value;
        ctx.flags.sig = 1;
        break;
    case 'f':
        ctx.pcr_file_path = value;
        ctx.flags.pcr = 1;
        break;
    case 'e':
        ctx.eventlog_path = value;
        ctx.flags.eventlog = 1;
        break;
    case 'l':
        ctx.pcr_selection_string = value;
        break;
        /* no default */
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
            { "hash-algorithm",     required_argument, NULL, 'g' },
            { "message",            required_argument, NULL, 'm' },
            { "format",             required_argument, NULL, 'F' },
            { "signature",          required_argument, NULL, 's' },
            { "eventlog",           required_argument, NULL, 'e' },
            { "pcr",                required_argument, NULL, 'f' },
            { "pcr-list",           required_argument, NULL, 'l' },
            { "public",             required_argument, NULL, 'u' },
            { "qualification",      required_argument, NULL, 'q' },
    };


    *opts = tpm2_options_new("g:m:F:s:u:f:q:e:l:", ARRAY_LEN(topts), topts,
            on_option, NULL, TPM2_OPTIONS_NO_SAPI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(ectx);
    UNUSED(flags);

    /* initialize and process */
    tool_rc rc = init();
    if (rc != tool_rc_success) {
        return rc;
    }

    bool res = verify();
    if (!res) {
        LOG_ERR("Verify signature failed!");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("checkquote", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
