//**********************************************************************;
// Copyright (c) 2017, SUSE GmbH
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

#ifndef CONVERSION_H
#define CONVERSION_H

#include <stdbool.h>

#include <sapi/tpm20.h>

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
 * Loads a public key in the TSS format from a file.
 * @param public
 *  The public key to load
 * @param format
 * @param path
 * @return
 */
bool tpm2_convert_pubkey_load(TPM2B_PUBLIC *public, const char *path);

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
bool tpm2_convert_sig(TPMT_SIGNATURE *signature, tpm2_convert_sig_fmt format,
        const char *path);

#endif /* CONVERSION_H */
