#ifndef SRC_PASSWORD_UTIL_H_
#define SRC_PASSWORD_UTIL_H_

#include <sapi/tpm20.h>

/**
 * Convert a password argument to a valid TPM2B_AUTH structure. Passwords can
 * be specified in two forms: string and hex-string and are identified by a
 * prefix of str: and hex: respectively. No prefix assumes the str form.
 *
 * For example, a string can be specified as:
 * "1234"
 * "str:1234"
 *
 * And a hexstring via:
 * "hex:1234abcd"
 *
 * Strings are copied verbatim to the TPM2B_AUTH buffer without the terminating NULL byte,
 * Hex strings differ only from strings in that they are converted to a byte array when
 * storing. At the end of storing, the size field is set to the size of bytes of the
 * password.
 *
 * If your password starts with a hex: prefix and you need to escape it, just use the string
 * prefix to escape it, like so:
 * "str:hex:password"
 *
 * @param password
 *  The optarg containing the password string.
 * @param dest
 *  The TPM2B_AUTH structure to copy the string into.
 * @return
 *  true on success, false on failure.
 */
bool tpm2_password_util_from_optarg(const char *password, TPM2B_AUTH *dest);

#endif /* SRC_PASSWORD_UTIL_H_ */
