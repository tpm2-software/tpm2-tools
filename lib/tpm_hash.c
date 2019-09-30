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
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "files.h"
#include "tpm_hash.h"
#include "tpm2_util.h"

#define TSS2_APP_HMAC_RC_FAILED TSS2_RC_LAYER(1) | 0x1

TSS2_RC tpm_hash_compute_data(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST *result, TPMT_TK_HASHCHECK *validation) {

    FILE *mem = fmemopen(buffer, length, "rb");
    if (!mem) {
        LOG_ERR("Error converting buffer to memory stream: %s",
                strerror(errno));
        return TSS2_APP_HMAC_RC_FAILED;
    }

    TSS2_RC rc = tpm_hash_file(sapi_context, halg, hierarchy, mem, result, validation);

    fclose(mem);

    return rc;
}

TSS2_RC tpm_hash_sequence(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hash_alg,
        TPMI_RH_HIERARCHY hierarchy, size_t num_buffers,
        TPM2B_DIGEST *buffer_list, TPM2B_DIGEST *result,
        TPMT_TK_HASHCHECK *validation) {

    TPM2B_AUTH null_auth = { .size = 0 };
    TPMI_DH_OBJECT sequence_handle;
    UINT32 rval = Tss2_Sys_HashSequenceStart(sapi_context, 0, &null_auth,
            hash_alg, &sequence_handle, 0);
    if (rval != TPM2_RC_SUCCESS) {
        return rval;
    }

    TSS2L_SYS_AUTH_COMMAND cmd_auth_array = { 1, {{.sessionHandle=TPM2_RS_PW}}};
    unsigned i;
    for (i = 0; i < num_buffers; i++) {
        rval = Tss2_Sys_SequenceUpdate(sapi_context, sequence_handle,
                &cmd_auth_array, (TPM2B_MAX_BUFFER *) &buffer_list[i], 0);

        if (rval != TPM2_RC_SUCCESS) {
            return rval;
        }
    }

    TPM2B_MAX_BUFFER empty_buffer = TPM2B_EMPTY_INIT;
    return Tss2_Sys_SequenceComplete(sapi_context, sequence_handle,
            &cmd_auth_array, &empty_buffer, hierarchy,
            result, validation, NULL);
}

TSS2_RC tpm_hash_file(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST *result,
        TPMT_TK_HASHCHECK *validation) {

    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;
    TPMI_DH_OBJECT sequenceHandle;

    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = { 1, {{.sessionHandle = TPM2_RS_PW, 
            .nonce = TPM2B_EMPTY_INIT, .hmac = TPM2B_EMPTY_INIT,
            .sessionAttributes = 0, }}};
    unsigned long file_size = 0;

    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /* If we can get the file size and its less than 1024, just do it in one hash invocation */
    if (res && file_size <= TPM2_MAX_DIGEST_BUFFER) {

        TPM2B_MAX_BUFFER buffer = { .size = file_size };

        res = files_read_bytes(input, buffer.buffer, buffer.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return TSS2_APP_HMAC_RC_FAILED;
        }

        return Tss2_Sys_Hash(sapi_context, NULL, &buffer, halg,
            hierarchy, result, validation, NULL);
    }

    /*
     * Size is either unkown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    TSS2_RC rval = Tss2_Sys_HashSequenceStart(sapi_context, NULL, &nullAuth,
            halg, &sequenceHandle, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Tss2_Sys_HashSequenceStart failed: 0x%X", rval);
        return rval;
    }

    /* If we know the file size, we decrement the amount read and terminate the loop
     * when 1 block is left, else we go till feof.
     */
    size_t left = file_size;
    bool use_left = !!res;

    TPM2B_MAX_BUFFER data;

    bool done = false;
    while (!done) {

        size_t bytes_read = fread(data.buffer, 1,
                BUFFER_SIZE(typeof(data), buffer), input);
        if (ferror(input)) {
            LOG_ERR("Error reading from input file");
            return TSS2_APP_HMAC_RC_FAILED;
        }

        data.size = bytes_read;

        /* if data was read, update the sequence */
        rval = Tss2_Sys_SequenceUpdate(sapi_context, sequenceHandle,
                &cmdAuthArray, &data, NULL);
        if (rval != TPM2_RC_SUCCESS) {
            return rval;
        }

        if (use_left) {
            left -= bytes_read;
            if (left <= TPM2_MAX_DIGEST_BUFFER) {
                done = true;
                continue;
            }
        } else if (feof(input)) {
            done = true;
        }
    } /* end file read/hash update loop */

    if (use_left) {
        data.size = left;
        bool res = files_read_bytes(input, data.buffer, left);
        if (!res) {
            LOG_ERR("Error reading from input file.");
            return TSS2_APP_HMAC_RC_FAILED;
        }
    } else {
        data.size = 0;
    }

    return Tss2_Sys_SequenceComplete(sapi_context, sequenceHandle,
            &cmdAuthArray, &data, hierarchy, result, validation,
            NULL);
}
