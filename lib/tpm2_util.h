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
#ifndef STRING_BYTES_H
#define STRING_BYTES_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <sapi/tpm20.h>

#include "tpm2_error.h"

#if defined (__GNUC__)
#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))
#else
#define COMPILER_ATTR(...)
#endif

#define xstr(s) str(s)
#define str(s) #s

#define UNUSED(x) (void)x

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))

#define TSS2_APP_RC_LAYER TSS2_RC_LAYER(5)

#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)
#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data = {   \
                    .size = 0 \
                }, \
                .userAuth = {   \
                    .size = 0 \
                } \
            } \
    }

#define TPMS_AUTH_COMMAND_INIT(session_handle) { \
        .sessionHandle = session_handle,\
	    .nonce = TPM2B_EMPTY_INIT, \
	    .sessionAttributes = TPMA_SESSION_CONTINUESESSION, \
	    .hmac = TPM2B_EMPTY_INIT \
    }

#define TPMS_AUTH_COMMAND_EMPTY_INIT TPMS_AUTH_COMMAND_INIT(0)


#define TPMT_TK_CREATION_EMPTY_INIT { \
        .tag = 0, \
		.hierarchy = 0, \
		.digest = TPM2B_EMPTY_INIT \
    }

#define TPML_PCR_SELECTION_EMPTY_INIT { \
        .count = 0, \
    } //ignore pcrSelections since count is 0.

#define TPMS_CAPABILITY_DATA_EMPTY_INIT { \
        .capability = 0, \
    } // ignore data since capability is 0.

#define TPMT_TK_HASHCHECK_EMPTY_INIT { \
		.tag = 0, \
		.hierarchy = 0, \
		.digest = TPM2B_EMPTY_INIT \
    }

#define TSS2L_SYS_AUTH_COMMAND_INIT(cnt, array) { \
        .count = cnt, \
        .auths = array, \
    }

/*
 * This macro is useful as a wrapper around SAPI functions to automatically
 * retry function calls when the RC is TPM2_RC_RETRY.
 */
#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while (tpm2_error_get(__result) == TPM2_RC_RETRY); \
        __result;                                          \
    })

int tpm2_util_hex_to_byte_structure(const char *inStr, UINT16 *byteLenth, BYTE *byteBuffer);

/**
 * Appends a TPM2B buffer to a MAX buffer.
 * @param result
 *  The MAX buffer to append to
 * @param append
 *  The buffer to append to result.
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_util_concat_buffer(TPM2B_MAX_BUFFER *result, TPM2B *append);

/**
 * Converts a numerical string into a uint32 value.
 * @param str
 *  The numerical string to convert.
 * @param value
 *  The value to store the conversion into.
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_util_string_to_uint32(const char *str, uint32_t *value);

/**
 * Converts a numerical string into a uint16 value.
 * @param str
 *  The numerical string to convert.
 * @param value
 *  The value to store the conversion into.
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_util_string_to_uint16(const char *str, uint16_t *value);

/**
 * Prints an xxd compatible hexdump to stdout if output is enabled,
 * ie no -Q option.
 *
 * @param data
 *  The data to print.
 * @param len
 *  The length of the data.
 * @param plain
 *  true for a plain hex string false for an xxd compatable
 *  dump.
 */
void tpm2_util_hexdump(const BYTE *data, size_t len, bool plain);

/**
 * Prints an xxd compatible hexdump to stdout if output is enabled,
 * ie no -Q option.
 *
 * @param fd
 *  A readable open file.
 * @param len
 *  The length of the data to read and print.
 * @param plain
 *  true for a plain hex string false for an xxd compatable
 *  dump.
 * @return
 *  true if len bytes were successfully read and printed,
 *  false otherwise
 */
bool tpm2_util_hexdump_file(FILE *fd, size_t len, bool plain);

/**
 * Prints a TPM2B as a hex dump.
 * @param buffer the TPM2B to print.
 */
static inline void tpm2_util_print_tpm2b(TPM2B *buffer) {

    return tpm2_util_hexdump(buffer->buffer, buffer->size, true);
}

/**
 * Reads a TPM2B object from FILE* and prints data in hex.
 * @param fd
 *  A readable open file.
 */
bool tpm2_util_print_tpm2b_file(FILE *fd);

/**
 * Copies a tpm2b from dest to src and clears dest if src is NULL.
 * If src is NULL, it is a NOP.
 * @param dest
 *  The destination TPM2B
 * @param src
 *  The source TPM2B
 * @return
 *  The number of bytes copied.
 */
UINT16 tpm2_util_copy_tpm2b(TPM2B *dest, TPM2B *src);

/**
 * Checks if the host is big endian
 * @return
 *  True of the host is big endian false otherwise.
 */
bool tpm2_util_is_big_endian(void);

/**
 * Swaps the endianess of 16 bit value.
 * @param data
 *  A 16 bit value to swap the endianess on.
 * @return
 * The 16 bit value with the endianess swapped.
 */
UINT16 tpm2_util_endian_swap_16(UINT16 data);

/**
 * Just like string_bytes_endian_convert_16 but for 32 bit values.
 */
UINT32 tpm2_util_endian_swap_32(UINT32 data);

/**
 * Just like string_bytes_endian_convert_16 but for 64 bit values.
 */
UINT64 tpm2_util_endian_swap_64(UINT64 data);

/**
 * Converts a 16 bit value from host endianess to network endianess.
 * @param data
 *  The data to possibly swap endianess.
 * @return
 *  The swapped data.
 */
UINT16 tpm2_util_hton_16(UINT16 data);

/**
 * Just like string_bytes_endian_hton_16 but for 32 bit values.
 */
UINT32 tpm2_util_hton_32(UINT32 data);

/**
 * Just like string_bytes_endian_hton_16 but for 64 bit values.
 */
UINT64 tpm2_util_hton_64(UINT64 data);

/**
 * Converts a 16 bit value from network endianess to host endianess.
 * @param data
 *  The data to possibly swap endianess.
 * @return
 *  The swapped data.
 */
UINT16 tpm2_util_ntoh_16(UINT16 data);

/**
 * Just like string_bytes_endian_ntoh_16 but for 32 bit values.
 */
UINT32 tpm2_util_ntoh_32(UINT32 data);

/**
 * Just like string_bytes_endian_ntoh_16 but for 64 bit values.
 */
UINT64 tpm2_util_ntoh_64(UINT64 data);

/**
 * Counts the number of set bits aka a population count.
 * @param data
 *  The data to count set bits in.
 * @return
 *  The number of set bits or population count.
 */
UINT32 tpm2_util_pop_count(UINT32 data);

/**
 * Prints whitespace indention for yaml output.
 * @param indent_count
 *  Number of times to indent
 */
void print_yaml_indent(size_t indent_count);

/**
 * Convert a TPM2B_PUBLIC into a yaml format and output if not quiet.
 * @param public
 *  The TPM2B_PUBLIC to output in YAML format.
 */
void tpm2_util_public_to_yaml(TPM2B_PUBLIC *public);


/**
 * Convert a TPMA_OBJECT to a yaml format and output if not quiet.
 * @param obj
 *  The TPMA_OBJECT attributes to print.
 */
void tpm2_util_tpma_object_to_yaml(TPMA_OBJECT obj);

#endif /* STRING_BYTES_H */
