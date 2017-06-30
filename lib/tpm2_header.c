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
#include <stdbool.h>

#include <sapi/tpm20.h>

#include "string-bytes.h"
#include "tpm2_header.h"

TPMI_ST_COMMAND_TAG get_command_tag(UINT8 *command_header) {

    tpm2_command_header *h = tpm2_command_header_from_bytes(command_header);
    return string_bytes_endian_ntoh_16(h->tag);
}

UINT32 get_command_size(UINT8 *command_header, bool include_header) {

    tpm2_command_header *h = tpm2_command_header_from_bytes(command_header);
    UINT32 size = string_bytes_endian_ntoh_32(h->size);

    return include_header ? size : size - TPM2_COMMAND_HEADER_SIZE;
}

TPM_CC get_command_code(UINT8 *command_header) {

    tpm2_command_header *h = tpm2_command_header_from_bytes(command_header);
    return string_bytes_endian_ntoh_32(h->command_code);
}

UINT8 *get_command_data(UINT8 *command_header) {

    tpm2_command_header *h = tpm2_command_header_from_bytes(command_header);

    UINT32 size = get_command_size(command_header, false);

    return size ? h->data : NULL;
}


TPM_ST get_response_tag(UINT8 *response_header) {

    tpm2_response_header *r = tpm2_response_header_from_bytes(response_header);
    return string_bytes_endian_ntoh_16(r->tag);
}

UINT32 get_response_size(UINT8 *response_header, bool include_header) {

    tpm2_response_header *r = tpm2_response_header_from_bytes(response_header);
    UINT32 size = string_bytes_endian_ntoh_32(r->size);

    return include_header ? size - TPM2_RESPONSE_HEADER_SIZE : size;
}

TSS2_RC get_response_code(UINT8 *response_header) {

    tpm2_response_header *r = tpm2_response_header_from_bytes(response_header);
    return string_bytes_endian_ntoh_32(r->response_code);
}

UINT8 *get_response_data(UINT8 *response_header) {

    tpm2_response_header *r = tpm2_response_header_from_bytes(response_header);

    UINT32 size = get_response_size(response_header, false);

    return size ? r->data : NULL;
}
