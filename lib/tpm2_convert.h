/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CONVERSION_H
#define CONVERSION_H

#include <stdbool.h>

#include <openssl/evp.h>

#include <tss2/tss2_sys.h>

typedef enum tpm2_convert_pubkey_fmt tpm2_convert_pubkey_fmt;
enum tpm2_convert_pubkey_fmt {
    pubkey_format_tss,
    pubkey_format_pem,
    pubkey_format_der,
    pubkey_format_tpmt,
    pubkey_format_err
};

typedef enum tpm2_convert_sig_fmt tpm2_convert_sig_fmt;
enum tpm2_convert_sig_fmt {
    signature_format_tss,
    signature_format_plain,
    signature_format_err
};

typedef enum tpm2_convert_pcrs_output_fmt tpm2_convert_pcrs_output_fmt;
enum tpm2_convert_pcrs_output_fmt {
    pcrs_output_format_values,
    pcrs_output_format_serialized,
    pcrs_output_format_err
};

/**
 * Parses the given command line PCRS file output format option string and
 * returns the corresponding pcrs_output_fmt enum value.
 *
 * LOG_ERR is used to communicate errors.
 *
 * @return
 *   On error pcrs_output_format_err is returned.
 */
tpm2_convert_pcrs_output_fmt tpm2_convert_pcrs_output_fmt_from_optarg(
    const char *label);

/**
 * Parses the given command line public key format option string and returns
 * the corresponding pubkey_format enum value.
 *
 * LOG_ERR is used to communicate errors.
 *
 * @return
 *   On error pubkey_format_err is returned.
 */
tpm2_convert_pubkey_fmt tpm2_convert_pubkey_fmt_from_optarg(const char *label);

/**
 * Converts the given public key structure into the requested target format
 * and writes the result to the given file system path.
 *
 * LOG_ERR is used to communicate errors.
 */
bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path);

/**
 * Converts the given RSA public key structure into the EVP_PKEY.
 *
 * @param public
 *  TPM2 public key structure structure.
 * @return
 *   OpenSSL key structure, or NULL on error.
 */
EVP_PKEY *convert_pubkey_RSA(TPMT_PUBLIC *public);

/**
 * Converts the given ECC public key structure into the EVP_PKEY.
 *
 * @param public
 *  TPM2 public key structure structure.
 * @return
 *   OpenSSL key structure, or NULL on error.
 */
EVP_PKEY *convert_pubkey_ECC(TPMT_PUBLIC *public);

/**
 * Parses the given command line signature format option string and returns
 * the corresponding signature_format enum value.
 *
 * LOG_ERR is used to communicate errors.
 *
 * @return
 *   On error signature_format_err is returned.
 */
tpm2_convert_sig_fmt tpm2_convert_sig_fmt_from_optarg(const char *label);

/**
 * Converts the given signature data into the requested target format and
 * writes the result to the given file system path.
 *
 * LOG_ERR is used to communicate errors.
 */
bool tpm2_convert_sig_save(TPMT_SIGNATURE *signature,
        tpm2_convert_sig_fmt format, const char *path);

/**
 * Like tpm2_convert_save with the "plain" signature option.
 *
 * @param size
 *  The size of the signature buffer.
 * @param signature
 *  The signature to convert.
 * @return
 *  NULL on error or a buffer of size bytes to be freed by the caller
 *  via free(2).
 */
UINT8 *tpm2_convert_sig(UINT16 *size, TPMT_SIGNATURE *signature);

/**
 * Load a signature from path and convert the format
 * @param path
 *  The path to load the signature from.
 * @param format
 *  The tss signature format
 * @param sig_alg
 *  The algorithm used for the signature. Only RSASSA (RSA PKCS1.5) signatures accepted.
 * @param halg
 *  The hashing algorithm used.
 * @param signature
 *  The signature structure to output too.
 * @return
 *  true on success, false on error.
 */
bool tpm2_convert_sig_load(const char *path, tpm2_convert_sig_fmt format,
        TPMI_ALG_SIG_SCHEME sig_alg, TPMI_ALG_HASH halg,
        TPMT_SIGNATURE *signature);

/**
 * Given a file, loads up the plain format of the signature. Probing to determine
 * if its a TSS buffer (using libmu errors as the detector) or a plain OSSL style
 * signature.
 * into a buffer.
 * @param path
 *  The file path containing the signature.
 * @param signature
 *  The plain signature bytes.
 * @param halg:
 *  If the signature scheme is *tss* also provide the hash algorithm, else
 *  set it to TPM2_ALG_NULL.
 * @return
 *  true on success, false on error.
 */
bool tpm2_convert_sig_load_plain(const char *path,
        TPM2B_MAX_BUFFER *signature, TPMI_ALG_HASH *halg);

bool tpm2_public_load_pkey(const char *path, EVP_PKEY **pkey);

/**
 * Encode a binary buffer to a Base64-encoded String.
 * @param buffer
 *  The binary buffer.
 * @param buffer_length:
 *  The length of the binary buffer.
 * @param base64
 *  The resulting Base64-encoded String.
 * @return
 *  true on success, false on error.
 */
bool tpm2_base64_encode(BYTE *buffer, size_t buffer_length, char *base64);

/**
 * Decode a Base64-encoded String to a binary buffer.
 * @param base64
 *  The Base64-encoded String.
 * @param buffer
 *  The resulting binary buffer, valid on success.
 * @param buffer_length:
 *  The length of the resulting binary buffer, valid on success.
 * @return
 *  true on success, false on error.
 */
bool tpm2_base64_decode(char *base64, BYTE *buffer, size_t *buffer_length);

#endif /* CONVERSION_H */
