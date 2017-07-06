#ifndef SRC_PASSWORD_UTIL_H_
#define SRC_PASSWORD_UTIL_H_

#include <sapi/tpm20.h>

/**
 * Copies a password stored in a TPM2B_AUTH structure, converting from hex if necessary, into
 * another TPM2B_AUTh structure. Source password and auth structures can be the same pointer.
 * @param password
 *  The source password.
 * @param is_hex
 *  True if the password contained in password is hex encoded.
 * @param description
 *  The description of the key used for error reporting.
 * @param auth
 *  The destination auth structure to copy the key into.
 * @return
 *  True on success and False on failure.
 */
bool password_tpm2_util_to_auth(TPM2B_AUTH *password, bool is_hex, const char *description,
        TPM2B_AUTH *auth);

/**
 * Copies a C string password into a TPM2B_AUTH structure. It logs an error on failure.
 *
 * Note: Use of a TPM2B_AUTH structure is for proper size allocation reporting and having
 * a size parameter to avoid duplicate strlen() calls.
 *
 * @param password
 *  The C string password to copy.
 * @param description
 *  A description of the password being copied for error reporting purposes.
 * @param dest
 *  The destination TPM2B_AUTH structure.
 * @return
 *  True on success, False on error.
 */
bool password_tpm2_util_copy_password(const char *password, const char *description, TPM2B_AUTH *dest);

#endif /* SRC_PASSWORD_UTIL_H_ */
