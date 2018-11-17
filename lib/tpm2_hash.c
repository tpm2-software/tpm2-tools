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

static bool tpm2_hash_common(   TSS2_SYS_CONTEXT    *sapi_context,
                                TPMI_ALG_HASH       halg,
                                TPMI_RH_HIERARCHY   hierarchy,
                                FILE                *infilep,
                                BYTE                *inbuffer,
                                UINT16              inbuffer_len,
                                TPM2B_DIGEST        *result,
                                TPMT_TK_HASHCHECK   *validation)
{
    bool res, use_left, done;
    unsigned long left;
    size_t bytes_read;
    TSS2_RC rval;
    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;
    TPMI_DH_OBJECT sequenceHandle;
    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = { 1, { {  .sessionHandle = TPM2_RS_PW,
                                                    .nonce = TPM2B_EMPTY_INIT,
                                                    .hmac = TPM2B_EMPTY_INIT,
                                                    .sessionAttributes = 0, }}};
    TPM2B_MAX_BUFFER buffer;

    /*  if we're using infilep, get file size */
    if (!!infilep) {
        /* Suppress error reporting with NULL path */
        use_left = files_get_file_size(infilep, &left, NULL);
    } else {
        /*  if we're using inbuffer, inbuffer_len is valid*/
        left = inbuffer_len;
        use_left = true;
    }

    /* if data length is non-zero (valid) and less than 1024, just do it in one
       hash invocation */
    if (use_left && left <= TPM2_MAX_DIGEST_BUFFER) {
        buffer.size = left;
        if (!!infilep) {
            res = files_read_bytes(infilep, buffer.buffer, buffer.size);
            if (!res) {
                LOG_ERR("Error reading input file!");
            }
        } else {
            memcpy(buffer.buffer, inbuffer, buffer.size);
            res = true;
        }

        if (res) {
            rval = TSS2_RETRY_EXP( Tss2_Sys_Hash(   sapi_context,
                                                    NULL,
                                                    &buffer,
                                                    halg,
                                                    hierarchy,
                                                    result,
                                                    validation,
                                                    NULL));
            if (rval != TSS2_RC_SUCCESS) {
                LOG_PERR(Tss2_Sys_Hash, rval);
                res = false;
            } else {
                res = true;
            }
        }
    } else {
        /*
         * length is either unknown because the FILE * is a fifo, or it's too
         * big to do in a single hash call. Based on the size figure out the
         * chunks to loop over, if possible. This way we can call Complete with
         * data.
         */
        rval = TSS2_RETRY_EXP( Tss2_Sys_HashSequenceStart( sapi_context,
                                                            NULL,
                                                            &nullAuth,
                                                            halg,
                                                            &sequenceHandle,
                                                            NULL) );
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_HashSequenceStart, rval);
            res = false;
        } else {
            res = true;
        }

        /* If we know the file size, we decrement the amount read and terminate
         * the loop when 1 block is left, else we go till feof.
         */
        done = false;
        while (res && !done) {
            /*  if we're using infilep, read the file. Otherwise, directly
                copy into our local buffer. */
            buffer.size = BUFFER_SIZE(typeof(buffer), buffer);
            if(!!infilep){
                bytes_read = fread( buffer.buffer, 1, buffer.size, infilep);
                if (ferror(infilep)) {
                    LOG_ERR("Error reading from input file");
                    res = false;
                } else {
                    buffer.size = bytes_read;
                    res = true;
                }
            } else {
                memcpy(buffer.buffer, inbuffer, buffer.size);
                inbuffer = inbuffer + buffer.size;
                res = true;
            }

            if (res) {
                rval = TSS2_RETRY_EXP( Tss2_Sys_SequenceUpdate( sapi_context,
                                                                sequenceHandle,
                                                                &cmdAuthArray,
                                                                &buffer,
                                                                NULL) );
                if (rval != TPM2_RC_SUCCESS) {
                    LOG_PERR(Tss2_Sys_SequenceUpdate, rval);
                    res = false;
                } else {
                    if (use_left) {
                        left -= buffer.size;
                        if (left <= TPM2_MAX_DIGEST_BUFFER) {
                            done = true;
                            continue;
                        }
                    } else if (!!infilep && feof(infilep)) {
                        done = true;
                    }
                }
            }
        } /* end file read/hash update loop */

        /*  if there is data left, get the last bit of data from the file or
            buffer or set the size to zero */
        if (res && use_left) {
            buffer.size = left;
            if(!!infilep){
                res = files_read_bytes(infilep, buffer.buffer, buffer.size);
                if (!res) {
                    LOG_ERR("Error reading from input file.");
                }
            } else {
                memcpy(buffer.buffer, inbuffer, buffer.size);
            }
        } else {
            buffer.size = 0;
        }

        if (res) {
            rval = TSS2_RETRY_EXP( Tss2_Sys_SequenceComplete( sapi_context,
                                                                sequenceHandle,
                                                                &cmdAuthArray,
                                                                &buffer,
                                                                hierarchy,
                                                                result,
                                                                validation,
                                                                NULL) );
            if (rval != TSS2_RC_SUCCESS) {
                LOG_PERR(Tss2_Sys_SequenceComplete, rval);
                res = false;
            }
        }
    } /* end of start-update-complete hash branch */
    return res;
}

bool tpm2_hash_compute_data(TSS2_SYS_CONTEXT    *sapi_context,
                            TPMI_ALG_HASH       halg,
                            TPMI_RH_HIERARCHY   hierarchy,
                            BYTE                *buffer,
                            UINT16              length,
                            TPM2B_DIGEST        *result,
                            TPMT_TK_HASHCHECK   *validation)
{
    return (!!buffer) && tpm2_hash_common( sapi_context,
                                            halg,
                                            hierarchy,
                                            NULL,
                                            buffer,
                                            length,
                                            result,
                                            validation);
}

bool tpm2_hash_file(TSS2_SYS_CONTEXT    *sapi_context,
                    TPMI_ALG_HASH       halg,
                    TPMI_RH_HIERARCHY   hierarchy,
                    FILE                *input,
                    TPM2B_DIGEST        *result,
                    TPMT_TK_HASHCHECK   *validation)
{
    return (!!input) && tpm2_hash_common( sapi_context,
                                            halg,
                                            hierarchy,
                                            input,
                                            NULL,
                                            0,
                                            result,
                                            validation);
}