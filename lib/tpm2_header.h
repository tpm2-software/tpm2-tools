/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TPM2_HEADER_H
#define TPM2_HEADER_H

#include <stdbool.h>

#include <sapi/tpm20.h>

#include "tpm2_util.h"

#define TPM2_COMMAND_HEADER_SIZE  (sizeof(tpm2_command_header))
#define TPM2_RESPONSE_HEADER_SIZE (sizeof(tpm2_response_header))

#define TPM2_MAX_SIZE 4096

typedef union tpm2_command_header tpm2_command_header;
union tpm2_command_header {
    struct {
        TPMI_ST_COMMAND_TAG tag; // uint16
        UINT32 size; //
        TPM2_CC command_code;
        UINT8 data[];
    } __attribute__((packed));
    UINT8 bytes[0];
};

typedef union tpm2_response_header tpm2_response_header;
union tpm2_response_header {
    struct {
        TPM2_ST tag;
        UINT32 size;
        TSS2_RC response_code;
        UINT8 data[];
    } __attribute__((packed));
    UINT8 bytes[0];
};

/**
 * Converts a byte-array to a tpm2_command_header struct.
 * @param h
 *  The byte array to convert to a tpm2_command_header.
 * @return
 *  A converted byte array.
 */
static inline tpm2_command_header *tpm2_command_header_from_bytes(UINT8 *h) {
    return (tpm2_command_header *)h;
}

/**
 * Converts a byte-array to a tpm2_response_header struct.
 * @param h
 *  The byte array to convert to a tpm2_response_header.
 * @return
 *  A converted byte array.
 */
static inline tpm2_response_header *tpm2_response_header_from_bytes(UINT8 *h) {
    return (tpm2_response_header *)h;
}

/**
 * Retrieves the command tag from a command converting to host
 * endianess.
 * @param command
 * @return
 */
static inline TPMI_ST_COMMAND_TAG tpm2_command_header_get_tag(tpm2_command_header *command) {

    return tpm2_util_ntoh_16(command->tag);
}

/**
 * Retrieves the command size from a command converting to host
 * endianess.
 * @param command
 * @param include_header
 * @return
 */
static inline UINT32 tpm2_command_header_get_size(tpm2_command_header *command, bool include_header) {

    UINT32 size = tpm2_util_ntoh_32(command->size);
    return include_header ? size : size - TPM2_COMMAND_HEADER_SIZE;
}

/**
 * Retrieves the command code from a command converting to host
 * endianess.
 * @param command
 * @return
 */
static inline TPM2_CC tpm2_command_header_get_code(tpm2_command_header *command) {

    return tpm2_util_ntoh_32(command->command_code);
}

/**
 * Retrieves command data, if present.
 * @param command
 *  The command to check for following data.
 * @return The command data or NULL if not present.
 */
static inline UINT8 *tpm2_command_header_get_data(tpm2_command_header *command) {

    UINT32 size = tpm2_command_header_get_size(command, false);
    return size ? command->data : NULL;
}

/**
 * Retrieves the response size from a response header converting to host
 * endianess.
 * @param response_header
 * @param include_header
 * @return
 */
static inline UINT32 tpm2_response_header_get_size(tpm2_response_header *response, bool include_header) {

    UINT32 size = tpm2_util_ntoh_32(response->size);
    return include_header ? size : size - TPM2_RESPONSE_HEADER_SIZE;
}

/**
 * Retrieves the response tag from a response header converting to host
 * endianess.
 * @param response_header
 * @return
 */
static inline TPM2_ST tpm2_response_header_get_tag(tpm2_response_header *response) {

    return tpm2_util_ntoh_16(response->tag);
}

/**
 * Retrieves the response code from a response header converting to host
 * endianess.
 * @param response_header
 * @return
 */
static inline TSS2_RC tpm2_response_header_get_code(tpm2_response_header *response) {

    return tpm2_util_ntoh_32(response->response_code);
}

/**
 * Retrieves response data, if present.
 * @param response_header
 *  The response_header to check for following data.
 * @return The response data or NULL if not present.
 */
static inline UINT8 *tpm2_response_header_get_data(tpm2_response_header *response) {


    UINT32 size = tpm2_response_header_get_size(response, false);
    return size ? response->data : NULL;
}

#endif /* TPM2_HEADER_H */
