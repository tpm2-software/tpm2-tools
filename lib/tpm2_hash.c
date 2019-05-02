/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
//**********************************************************************;
#include <errno.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "files.h"
#include "tpm2_hash.h"
#include "tpm2_util.h"

static bool tpm2_hash_common(   ESYS_CONTEXT        *ectx,
                                TPMI_ALG_HASH       halg,
                                TPMI_RH_HIERARCHY   hierarchy,
                                FILE                *infilep,
                                BYTE                *inbuffer,
                                UINT16              inbuffer_len,
                                TPM2B_DIGEST        **result,
                                TPMT_TK_HASHCHECK   **validation)
{
    bool res, use_left, done;
    unsigned long left;
    size_t bytes_read;
    TSS2_RC rval;
    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;
    TPMI_DH_OBJECT sequenceHandle;
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
            rval = Esys_Hash(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &buffer, halg, hierarchy, result, validation);
            if (rval != TSS2_RC_SUCCESS) {
                LOG_PERR(Esys_Hash, rval);
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
        rval = Esys_HashSequenceStart(ectx,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &nullAuth, halg, &sequenceHandle);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Esys_HashSequenceStart, rval);
            res = false;
        } else {
            res = true;
        }

        rval = Esys_TR_SetAuth(ectx, sequenceHandle, &nullAuth);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_TR_SetAuth, rval);
            res = false;
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
                rval = Esys_SequenceUpdate(ectx, sequenceHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &buffer);
                if (rval != TPM2_RC_SUCCESS) {
                    LOG_PERR(Esys_SequenceUpdate, rval);
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
            rval = Esys_SequenceComplete(ectx, sequenceHandle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &buffer, hierarchy, result, validation);
            if (rval != TSS2_RC_SUCCESS) {
                LOG_PERR(Eys_SequenceComplete, rval);
                res = false;
            }
        }
    } /* end of start-update-complete hash branch */
    return res;
}

bool tpm2_hash_compute_data(ESYS_CONTEXT        *ectx,
                            TPMI_ALG_HASH       halg,
                            TPMI_RH_HIERARCHY   hierarchy,
                            BYTE                *buffer,
                            UINT16              length,
                            TPM2B_DIGEST        **result,
                            TPMT_TK_HASHCHECK   **validation)
{
    return (!!buffer) && tpm2_hash_common( ectx,
                                            halg,
                                            hierarchy,
                                            NULL,
                                            buffer,
                                            length,
                                            result,
                                            validation);
}

bool tpm2_hash_file(ESYS_CONTEXT        *ectx,
                    TPMI_ALG_HASH       halg,
                    TPMI_RH_HIERARCHY   hierarchy,
                    FILE                *input,
                    TPM2B_DIGEST        **result,
                    TPMT_TK_HASHCHECK   **validation)
{
    return (!!input) && tpm2_hash_common( ectx,
                                            halg,
                                            hierarchy,
                                            input,
                                            NULL,
                                            0,
                                            result,
                                            validation);
}