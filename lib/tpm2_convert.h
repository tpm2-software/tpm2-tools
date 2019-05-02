/* SPDX-License-Identifier: BSD-2-Clause */
//**********************************************************************;
// Copyright (c) 2017, SUSE GmbH
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#ifndef CONVERSION_H
#define CONVERSION_H

#include <stdbool.h>

#include <tss2/tss2_sys.h>

typedef enum tpm2_convert_pubkey_fmt tpm2_convert_pubkey_fmt;
enum tpm2_convert_pubkey_fmt {
    pubkey_format_tss,
    pubkey_format_pem,
    pubkey_format_der,
    pubkey_format_err
};

typedef enum tpm2_convert_sig_fmt tpm2_convert_sig_fmt;
enum tpm2_convert_sig_fmt {
    signature_format_tss,
    signature_format_plain,
    signature_format_err
};

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
bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public, tpm2_convert_pubkey_fmt format, const char *path);

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
bool tpm2_convert_sig_save(TPMT_SIGNATURE *signature, tpm2_convert_sig_fmt format,
        const char *path);

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
bool tpm2_convert_sig_load(const char *path, tpm2_convert_sig_fmt format, TPMI_ALG_SIG_SCHEME sig_alg,
        TPMI_ALG_HASH halg, TPMT_SIGNATURE *signature);

#endif /* CONVERSION_H */
