//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
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
#ifndef SRC_PASSWORD_UTIL_H_
#define SRC_PASSWORD_UTIL_H_

#include <tss2/tss2_sys.h>

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
 * @param password
 *  The optarg containing the password string.
 * @param dest
 *  The TPM2B_AUTH structure to copy the string into.
 * @param session
 *  If a session is used, returns the session data.
 * @return
 *  true on success, false on failure.
 */
bool tpm2_auth_util_from_optarg(TSS2_SYS_CONTEXT *sys_ctx,
        const char *password, TPMS_AUTH_COMMAND *auth,
        tpm2_session **session);

#endif /* SRC_PASSWORD_UTIL_H_ */
