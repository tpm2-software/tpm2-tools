/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_HEADER_H
#define TPM2_HEADER_H

#include <stdbool.h>

#include <tss2/tss2_sys.h>

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
    }__attribute__((packed));
    UINT8 bytes[0];
};

typedef union tpm2_response_header tpm2_response_header;
union tpm2_response_header {
    struct {
        TPM2_ST tag;
        UINT32 size;
        TSS2_RC response_code;
        UINT8 data[];
    }__attribute__((packed));
    UINT8 bytes[0];
};

/**
 * Converts a byte-array to a tpm2_command_header struct.
 * @param h
 *  The byte array to convert to a tpm2_command_header.
 * @return
 *  A converted byte array.
 */
static inline const tpm2_command_header *tpm2_command_header_from_bytes(const UINT8 *h) {

    return (tpm2_command_header *) h;
}

/**
 * Converts a byte-array to a tpm2_response_header struct.
 * @param h
 *  The byte array to convert to a tpm2_response_header.
 * @return
 *  A converted byte array.
 */
static inline const tpm2_response_header *tpm2_response_header_from_bytes(const UINT8 *h) {

    return (tpm2_response_header *) h;
}

/**
 * Retrieves the command tag from a command converting to host
 * endianess.
 * @param command
 * @return
 */
static inline TPMI_ST_COMMAND_TAG tpm2_command_header_get_tag(
        const tpm2_command_header *command) {

    return tpm2_util_ntoh_16(command->tag);
}

/**
 * Retrieves the command size from a command converting to host
 * endianess.
 * @param command
 * @param include_header
 * @return
 */
static inline UINT32 tpm2_command_header_get_size(const tpm2_command_header *command,
        bool include_header) {

    UINT32 size = tpm2_util_ntoh_32(command->size);
    return include_header ? size : size - TPM2_COMMAND_HEADER_SIZE;
}

/**
 * Retrieves the command code from a command converting to host
 * endianess.
 * @param command
 * @return
 */
static inline TPM2_CC tpm2_command_header_get_code(const tpm2_command_header *command) {

    return tpm2_util_ntoh_32(command->command_code);
}

/**
 * Retrieves command data, if present.
 * @param command
 *  The command to check for following data.
 * @return The command data or NULL if not present.
 */
static inline const UINT8 *tpm2_command_header_get_data(const tpm2_command_header *command) {

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
static inline UINT32 tpm2_response_header_get_size(
        const tpm2_response_header *response, bool include_header) {

    UINT32 size = tpm2_util_ntoh_32(response->size);
    return include_header ? size : size - TPM2_RESPONSE_HEADER_SIZE;
}

/**
 * Retrieves the response tag from a response header converting to host
 * endianess.
 * @param response_header
 * @return
 */
static inline TPM2_ST tpm2_response_header_get_tag(
        const tpm2_response_header *response) {

    return tpm2_util_ntoh_16(response->tag);
}

/**
 * Retrieves the response code from a response header converting to host
 * endianess.
 * @param response_header
 * @return
 */
static inline TSS2_RC tpm2_response_header_get_code(
        const tpm2_response_header *response) {

    return tpm2_util_ntoh_32(response->response_code);
}

/**
 * Retrieves response data, if present.
 * @param response_header
 *  The response_header to check for following data.
 * @return The response data or NULL if not present.
 */
static inline const UINT8 *tpm2_response_header_get_data(
        const tpm2_response_header *response) {

    UINT32 size = tpm2_response_header_get_size(response, false);
    return size ? response->data : NULL;
}

#endif /* TPM2_HEADER_H */
