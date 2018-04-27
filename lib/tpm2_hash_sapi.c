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
#include <errno.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "log.h"
#include "files.h"
#include "tpm2_hash.h"
#include "tpm2_util.h"

bool tpm2_hash_compute_data_sapi(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST *result, TPMT_TK_HASHCHECK *validation) {

    FILE *mem = fmemopen(buffer, length, "rb");
    if (!mem) {
        LOG_ERR("Error converting buffer to memory stream: %s",
                strerror(errno));
        return false;
    }

    return tpm2_hash_file_sapi(sapi_context, halg, hierarchy, mem, result, validation);
}

bool tpm2_hash_file_sapi(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
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
            return false;
        }

        TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Hash(sapi_context, NULL, &buffer, halg,
            hierarchy, result, validation, NULL));
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_Hash, rval);
            return false;
        }

        return true;
    }

    /*
     * Size is either unknown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_HashSequenceStart(sapi_context, NULL, &nullAuth,
            halg, &sequenceHandle, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_HashSequenceStart, rval);
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
            return false;
        }

        data.size = bytes_read;

        /* if data was read, update the sequence */
        rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sapi_context, sequenceHandle,
                &cmdAuthArray, &data, NULL));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_SequenceUpdate, rval);
            return false;
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
            return false;
        }
    } else {
        data.size = 0;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceComplete(sapi_context, sequenceHandle,
            &cmdAuthArray, &data, hierarchy, result, validation,
            NULL));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_SequenceComplete, rval);
        return false;
    }

    return true;
}
