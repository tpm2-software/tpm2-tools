/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_CC_UTIL_H_
#define LIB_TPM2_CC_UTIL_H_

#include <stdbool.h>

#include <tss2/tss2_tpm2_types.h>

/**
 * Converts a string to a command code.
 * @param str
 *  The string to convert. The string is either the macro name
 *  of the command code provided by the tss2_tpm2_types.h header file or
 *  a numerical string understood by strtoul() with a base of 0.
 * @param cc
 *  The command code value.
 * @return
 *  True if successful, false otherwise.
 */
bool tpm2_cc_util_from_str(const char *str, TPM2_CC *cc);

/**
 * Given a command code, returns the name of the command as defined by the macro
 * names in tss2_tpm2_types.h. If the command is unknown, NULL is returned.
 * @param cc
 *  The command to decode.
 * @return
 *  A string or NULL.
 */
const char *tpm2_cc_util_to_str(TPM2_CC cc);

#endif /* LIB_TPM2_CC_UTIL_H_ */
