//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#ifndef LIB_TPM2_ERROR_H_
#define LIB_TPM2_ERROR_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

/**
 * Number of error layers
 */
#define TPM2_ERROR_TSS2_RC_LAYER_COUNT (TSS2_RC_LAYER_MASK >> TSS2_RC_LAYER_SHIFT)

/**
 * Mask for the error bits of tpm2 compliant return code.
 */
#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

/**
 * Retrieves the error bits from a TSS2_RC. The error bits are
 * contained in the first 2 octets.
 * @param rc
 *  The rc to query for the error bits.
 * @return
 *  The error bits.
 */
static inline UINT16 tpm2_error_get(TSS2_RC rc) {
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}

/**
 * A custom error handler prototype.
 * @param rc
 *  The rc to decode with only the error bits set, ie no need to mask the
 *  layer bits out. Handlers will never be invoked with the error bits set
 *  to 0, as zero always indicates success.
 * @return
 *  An error string describing the rc. If the handler cannot determine
 *  a valid response, it can return NULL indicating that the framework
 *  should just print the raw hexidecimal value of the error field of
 *  a tpm2_err_layer_rc.
 *  Note that this WILL NOT BE FREED by the caller,
 *  i.e. static.
 */
typedef const char *(*tpm2_error_handler)(TSS2_RC rc);

/**
 * Register or unregister a custom layer error handler.
 * @param layer
 *  The layer in which to register a handler for. It is an error
 *  to register for the following reserved layers:
 *    - TSS2_TPM_RC_LAYER  - layer  0
 *    - TSS2_SYS_RC_LAYER  - layer  8
 *    - TSS2_MU_RC_LAYER   - layer  9
 *    - TSS2_TCTI_RC_LAYER - layer 10
 * @param name
 *  A friendly layer name. It is an error for the name to be of
 *  length 0 or greater than 4.
 * @param handler
 *  The handler function to register or NULL to unregister.
 * @return
 *  True on success or False on error.
 */
bool tpm2_error_set_handler(UINT8 layer, const char *name,
        tpm2_error_handler handler);

/**
 * Given a TSS2_RC return code, provides a static error string in the format:
 * <layer-name>:<layer-specific-msg>.
 *
 * The layer-name section will either be the friendly name, or if no layer
 * handler is registered, the base10 layer number.
 *
 * The "layer-specific-msg" is layer specific and will contain details on the
 * error that occurred or the error code if it couldn't look it up.
 *
 * Known layer specific substrings:
 * TPM - The tpm layer produces 2 distinct format codes that allign with:
 *   - Section 6.6 of: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 *   - Section 39.4 of: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
 *
 *   The two formats are format 0 and format 1.
 *   Format 0 string format:
 *     - "<error|warn>(<version>): <description>
 *     - Examples:
 *       - error(1.2): bad tag
 *       - warn(2.0): the 1st handle in the handle area references a transient object or session that is not loaded
 *
 *   Format 1 string format:
 *      - <handle|session|parameter>(<index>):<description>
 *      - Examples:
 *        - handle(unk):value is out of range or is not correct for the context
 *        - tpm:handle(5):value is out of range or is not correct for the context
 *
 *   Note that passing TPM2_RC_SUCCESS results in the layer specific message of "success".
 *
 *   The System, TCTI and Marshaling (MU) layers, all define simple string
 *   returns analogous to strerror(3).
 *
 *   Unknown layers will have the layer number in decimal and then a layer specific string of
 *   a hex value representing the error code. For example: 9:0x3
 *
 * @param rc
 *  The error code to decode.
 * @return
 *  A human understandable error description string.
 */
const char *tpm2_error_str(TSS2_RC rc);

#endif /* LIB_TPM2_ERROR_H_ */
