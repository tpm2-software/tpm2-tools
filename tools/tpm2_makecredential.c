/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_identity_util.h"
#include "tpm2_options.h"
#include "tpm2_openssl.h"

typedef struct tpm_makecred_ctx tpm_makecred_ctx;
struct tpm_makecred_ctx {
    TPM2B_NAME object_name;
    char *out_file_path;
    char *input_secret_data;
    char *public_key_path; /* path to the public portion of an object */
    TPM2B_PUBLIC public;
    TPM2B_DIGEST credential;
    struct {
        UINT8 e :1;
        UINT8 s :1;
        UINT8 n :1;
        UINT8 o :1;
    } flags;

    char *key_type; //type of key attempting to load, defaults to auto attempt
};

static tpm_makecred_ctx ctx = {
    .object_name = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .credential = TPM2B_EMPTY_INIT,
};

static bool write_cred_and_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;

    FILE *fp = fopen(path, "wb+");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    result = files_write_header(fp, 1);
    if (!result) {
        LOG_ERR("Could not write version header");
        goto out;
    }

    result = files_write_16(fp, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential size");
        goto out;
    }

    result = files_write_bytes(fp, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential data");
        goto out;
    }

    result = files_write_16(fp, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret size");
        goto out;
    }

    result = files_write_bytes(fp, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static tool_rc make_external_credential_and_save(void) {

    /*
     * Get name_alg from the public key
     */
    TPMI_ALG_HASH name_alg = ctx.public.publicArea.nameAlg;

    /*
     * Generate and encrypt seed
     */
    TPM2B_DIGEST seed = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;
    unsigned char label[10] = { 'I', 'D', 'E', 'N', 'T', 'I', 'T', 'Y', 0 };
    bool res = tpm2_identity_util_share_secret_with_public_key(&seed,
            &ctx.public, label, 9, &encrypted_seed);
    if (!res) {
        LOG_ERR("Failed Seed Encryption\n");
        return tool_rc_general_error;
    }

    /*
     * Perform identity structure calculations (off of the TPM)
     */
    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            &ctx.public, &ctx.object_name, &seed, &hmac_key, &enc_key);

    /*
     * The ctx.credential needs to be marshalled into struct with
     * both size and contents together (to be encrypted as a block)
     */
    TPM2B_MAX_BUFFER marshalled_inner_integrity = TPM2B_EMPTY_INIT;
    marshalled_inner_integrity.size = ctx.credential.size
            + sizeof(ctx.credential.size);
    UINT16 cred_size = ctx.credential.size;
    if (!tpm2_util_is_big_endian()) {
        cred_size = tpm2_util_endian_swap_16(cred_size);
    }
    memcpy(marshalled_inner_integrity.buffer, &cred_size, sizeof(cred_size));
    memcpy(&marshalled_inner_integrity.buffer[2], ctx.credential.buffer,
            ctx.credential.size);

    /*
     * Perform inner encryption (encIdentity) and outer HMAC (outerHMAC)
     */
    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(name_alg, &ctx.object_name,
            &marshalled_inner_integrity, &hmac_key, &enc_key,
            &ctx.public.publicArea.parameters.rsaDetail.symmetric,
            &encrypted_sensitive, &outer_hmac);

    /*
     * Package up the info to save
     * cred_bloc = outer_hmac || encrypted_sensitive
     * secret = encrypted_seed (with pubEK)
     */
    TPM2B_ID_OBJECT cred_blob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);

    UINT16 outer_hmac_size = outer_hmac.size;
    if (!tpm2_util_is_big_endian()) {
        outer_hmac_size = tpm2_util_endian_swap_16(outer_hmac_size);
    }
    int offset = 0;
    memcpy(cred_blob.credential + offset, &outer_hmac_size,
            sizeof(outer_hmac.size));
    offset += sizeof(outer_hmac.size);
    memcpy(cred_blob.credential + offset, outer_hmac.buffer, outer_hmac.size);
    offset += outer_hmac.size;
    //NOTE: do NOT include the encrypted_sensitive size, since it is encrypted with the blob!
    memcpy(cred_blob.credential + offset, encrypted_sensitive.buffer,
            encrypted_sensitive.size);

    cred_blob.size = outer_hmac.size + encrypted_sensitive.size
            + sizeof(outer_hmac.size);

    return write_cred_and_secret(ctx.out_file_path, &cred_blob,
            &encrypted_seed) ? tool_rc_success : tool_rc_general_error;
}

static tool_rc make_credential_and_save(ESYS_CONTEXT *ectx) {
    TPM2B_ID_OBJECT *cred_blob;
    TPM2B_ENCRYPTED_SECRET *secret;
    ESYS_TR tr_handle = ESYS_TR_NONE;

    tool_rc rc = tpm2_loadexternal(ectx, 0, &ctx.public, TPM2_RH_NULL,
        &tr_handle, 0, TPM2_ALG_ERROR);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_makecredential(ectx, tr_handle,
            &ctx.credential, &ctx.object_name, &cred_blob,
            &secret);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_flush_context(ectx, tr_handle, NULL, TPM2_ALG_NULL);
    if (rc != tool_rc_success) {
        free(cred_blob);
        free(secret);
        return rc;
    }

    bool ret = write_cred_and_secret(ctx.out_file_path, cred_blob, secret);
    free(cred_blob);
    free(secret);
    return ret ? tool_rc_success : tool_rc_general_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'u':
        if (ctx.flags.e) {
            LOG_ERR("Specify public key with **-u** or **-e**, not both");
            return false;
        }
        ctx.public_key_path = value;
        ctx.flags.e = 1;
        break;
    case 'e':
        if (ctx.flags.e) {
            LOG_ERR("Specify encryption key with **-u** or **-e**, not both");
            return false;
        }
        ctx.public_key_path = value;
        ctx.flags.e = 1;
        break;
    case 's':
        ctx.input_secret_data = strcmp("-", value) ? value : NULL;
        ctx.flags.s = 1;
        break;
    case 'n':
        ctx.object_name.size = BUFFER_SIZE(TPM2B_NAME, name);
        int q;
        if ((q = tpm2_util_hex_to_byte_structure(value, &ctx.object_name.size,
                ctx.object_name.name)) != 0) {
            LOG_ERR("FAILED: %d", q);
            return false;
        }
        ctx.flags.n = 1;
        break;
    case 'o':
        ctx.out_file_path = value;
        ctx.flags.o = 1;
        break;
    case 'G':
        ctx.key_type = value;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"encryption-key",  required_argument, NULL, 'e'},
      {"public",          required_argument, NULL, 'u'},
      {"secret",          required_argument, NULL, 's'},
      {"name",            required_argument, NULL, 'n'},
      {"credential-blob", required_argument, NULL, 'o'},
      { "key-algorithm",  required_argument, NULL, 'G'},
    };

    *opts = tpm2_options_new("G:u:e:s:n:o:", ARRAY_LEN(topts), topts, on_option,
        NULL, TPM2_OPTIONS_OPTIONAL_SAPI);

    return *opts != NULL;
}

static void set_default_TCG_EK_template(TPMI_ALG_PUBLIC alg) {

    switch (alg) {
        case TPM2_ALG_RSA:
            ctx.public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                    TPM2_ALG_AES;
            ctx.public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
            ctx.public.publicArea.parameters.rsaDetail.symmetric.mode.aes =
                    TPM2_ALG_CFB;
            ctx.public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
            ctx.public.publicArea.parameters.rsaDetail.keyBits = 2048;
            ctx.public.publicArea.parameters.rsaDetail.exponent = 0;
            ctx.public.publicArea.unique.rsa.size = 256;
            break;
        case TPM2_ALG_ECC:
            ctx.public.publicArea.parameters.eccDetail.symmetric.algorithm =
                    TPM2_ALG_AES;
            ctx.public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
            ctx.public.publicArea.parameters.eccDetail.symmetric.mode.sym =
                    TPM2_ALG_CFB;
            ctx.public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
            ctx.public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
            ctx.public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
            ctx.public.publicArea.unique.ecc.x.size = 32;
            ctx.public.publicArea.unique.ecc.y.size = 32;
            break;
    }

    ctx.public.publicArea.objectAttributes =
          TPMA_OBJECT_RESTRICTED  | TPMA_OBJECT_ADMINWITHPOLICY
        | TPMA_OBJECT_DECRYPT     | TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;

    static const TPM2B_DIGEST auth_policy = {
        .size = 32,
        .buffer = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
        }
    };
    TPM2B_DIGEST *authp = &ctx.public.publicArea.authPolicy;
    *authp = auth_policy;

    ctx.public.publicArea.nameAlg = TPM2_ALG_SHA256;
}

static tool_rc process_input(tpm2_option_flags flags) {

    TPMI_ALG_PUBLIC alg = TPM2_ALG_NULL;
    if (ctx.key_type) {
        if (!flags.quiet) {
            LOG_WARN("Because **-G** is specified, assuming input encryption "
                     "public key is in PEM format.");
        }
        alg = tpm2_alg_util_from_optarg(ctx.key_type,
            tpm2_alg_util_flags_asymmetric);
        if (alg == TPM2_ALG_ERROR ||
           (alg != TPM2_ALG_RSA && alg != TPM2_ALG_ECC)) {
            LOG_ERR("Unsupported key type, got: \"%s\"", ctx.key_type);
            return tool_rc_general_error;
        }
    }

    if (ctx.public_key_path) {
        bool result = alg != TPM2_ALG_NULL ?
            tpm2_openssl_load_public(ctx.public_key_path, alg,
            &ctx.public) : files_load_public(ctx.public_key_path, &ctx.public);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    /*
     * Since it is a PEM we will fixate the key properties from TCG EK
     * template since we had to choose "a template".
     */
    if (ctx.key_type) {
        set_default_TCG_EK_template(alg);
    }

    if (!ctx.flags.s) {
        LOG_ERR("Specify the secret either as a file or a '-' for stdin");
        return tool_rc_option_error;
    }

    if (!ctx.flags.e || !ctx.flags.n || !ctx.flags.o) {
        LOG_ERR("Expected mandatory options e, n, o.");
        return tool_rc_option_error;
    }

    /*
     * Maximum size of the allowed secret-data size  to fit in TPM2B_DIGEST
     */
    ctx.credential.size = TPM2_SHA512_DIGEST_SIZE;

    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
        ctx.input_secret_data, &ctx.credential.size, ctx.credential.buffer);
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * If input was read from stdin, check if a larger data set was specified
     * and error out.
     */
    if (ctx.credential.size > TPM2_SHA512_DIGEST_SIZE) {
        LOG_ERR("Size is larger than buffer, got %d expected less than or equal"
        "to %d", ctx.credential.size, TPM2_SHA512_DIGEST_SIZE);
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = process_input(flags);
    if (rc != tool_rc_success) {
        return rc;
    }

    // Run it outside of a TPM
    return ectx ?
            make_credential_and_save(ectx) :
                make_external_credential_and_save();
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("makecredential", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
