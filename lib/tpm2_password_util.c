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
#include <stdbool.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_password_util.h"
#include "tpm2_util.h"

#define HEX_PREFIX "hex:"
#define HEX_PREFIX_LEN sizeof(HEX_PREFIX) - 1

#define STR_PREFIX "str:"
#define STR_PREFIX_LEN sizeof(STR_PREFIX) - 1

bool tpm2_password_util_from_optarg(const char *password, TPM2B_AUTH *dest) {

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (!is_hex) {

        /* str may or may not have the str: prefix */
        bool is_str_prefix = !strncmp(password, STR_PREFIX, STR_PREFIX_LEN);
        if (is_str_prefix) {
            password += STR_PREFIX_LEN;
        }

        /*
         * Per the man page:
         * "a return value of size or more means that the output was  truncated."
         */
        size_t wrote = snprintf((char *)&dest->buffer, BUFFER_SIZE(typeof(*dest), buffer), "%s", password);
        if (wrote >= BUFFER_SIZE(typeof(*dest), buffer)) {
            dest->size = 0;
            return false;
        }

        dest->size = wrote;

        return true;
    }

    /* if it is hex, then skip the prefix */
    password += HEX_PREFIX_LEN;

    dest->size = BUFFER_SIZE(typeof(*dest), buffer);
    int rc = tpm2_util_hex_to_byte_structure(password, &dest->size, dest->buffer);
    if (rc) {
        dest->size = 0;
        return false;
    }

    return true;
}
