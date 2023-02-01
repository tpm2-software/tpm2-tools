/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_PASSWORD_UTIL_H_
#define SRC_PASSWORD_UTIL_H_

#include <tss2/tss2_esys.h>

#include "tpm2_session.h"

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
 * @param ctx
 *  Enhanced System API (ESAPI) context
 * @param password
 *  The optarg containing the password string.
 * @param dest
 *  The TPM2B_AUTH structure to copy the string into.
 *  @ is_restricted
 *   True if it is restricted to only password session data.
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_auth_util_from_optarg(ESYS_CONTEXT *ctx, const char *password,
        tpm2_session **session, bool is_restricted);

/**
 * Set up authorisation for a handle and return a session handle for use in
 * ESAPI calls.
 *
 * @param ectx
 *  Enhanced System API (ESAPI) context
 * @param for_auth
 *  The target handle which needs authorization setting up
 * @param auth
 *  Auth command for the handle
 * @param session
 *  Session for the handle
 * @param handle
 *  The output handle for the session
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR for_auth,
        tpm2_session *session, ESYS_TR *handle);

/**
 * Populate a string password in a TPM2B_AUTH structure.
 *
 * @param password
 *   The string password or auth value.
 * @param auth
 *   The TPM2B_AUTH structure to populate.
 * @return
 *   Boolean indicating the success of the operation.
 */
bool handle_password(const char *password, TPM2B_AUTH *auth);

#endif /* SRC_PASSWORD_UTIL_H_ */
