/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_hash.h"

static tool_rc tpm2_hash_common(ESYS_CONTEXT *ectx, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *infilep, BYTE *inbuffer,
        UINT16 inbuffer_len, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation) {
    bool use_left = true, done;
    unsigned long left = inbuffer_len;
    size_t bytes_read;
    TPM2B_AUTH null_auth = TPM2B_EMPTY_INIT;
    TPMI_DH_OBJECT sequence_handle;
    TPM2B_MAX_BUFFER buffer;

    /*  if we're using infilep, get file size */
    if (!!infilep) {
        /* Suppress error reporting with NULL path */
        use_left = files_get_file_size(infilep, &left, NULL);
    }

    /* if data length is non-zero (valid) and less than 1024, just do it in one
     hash invocation */
    if (use_left && left <= TPM2_MAX_DIGEST_BUFFER) {
        buffer.size = left;
        if (!!infilep) {
            bool res = files_read_bytes(infilep, buffer.buffer, buffer.size);
            if (!res) {
                return tool_rc_general_error;
            }
        } else {
            memcpy(buffer.buffer, inbuffer, buffer.size);
        }

        return tpm2_hash(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                &buffer, halg, hierarchy, result, validation);
    }
    /*
     * length is either unknown because the FILE * is a fifo, or it's too
     * big to do in a single hash call. Based on the size figure out the
     * chunks to loop over, if possible. This way we can call Complete with
     * data.
     */
    tool_rc rc = tpm2_hash_sequence_start(ectx, &null_auth, halg, &sequence_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* If we know the file size, we decrement the amount read and terminate
     * the loop when 1 block is left, else we go till feof.
     */
    done = false;
    while (!done) {
        /*  if we're using infilep, read the file. Otherwise, directly
         copy into our local buffer. */
        buffer.size = BUFFER_SIZE(typeof(buffer), buffer);
        if (!!infilep) {
            bytes_read = fread(buffer.buffer, 1, buffer.size, infilep);
            if (ferror(infilep)) {
                LOG_ERR("Error reading from input file");
                return tool_rc_general_error;
            } else {
                buffer.size = bytes_read;
            }
        } else {
            memcpy(buffer.buffer, inbuffer, buffer.size);
            inbuffer = inbuffer + buffer.size;
        }

        rc = tpm2_sequence_update(ectx, sequence_handle, &buffer);
        if (rc != tool_rc_success) {
            return rc;
        }

        if (use_left) {
            left -= buffer.size;
            if (left <= TPM2_MAX_DIGEST_BUFFER) {
                done = true;
                continue;
            }
        } else if (!!infilep && feof(infilep)) {
            done = true;
        }
    } /* end file read/hash update loop */

    /*  if there is data left, get the last bit of data from the file or
     buffer or set the size to zero */
    if (use_left) {
        buffer.size = left;
        if (!!infilep) {
            bool res = files_read_bytes(infilep, buffer.buffer, buffer.size);
            if (!res) {
                LOG_ERR("Error reading from input file.");
                return tool_rc_general_error;
            }
        } else {
            memcpy(buffer.buffer, inbuffer, buffer.size);
        }
    } else {
        buffer.size = 0;
    }

    return tpm2_sequence_complete(ectx, sequence_handle,
            &buffer, hierarchy, result, validation);
}

tool_rc tpm2_hash_compute_data(ESYS_CONTEXT *ectx, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST **result, TPMT_TK_HASHCHECK **validation) {

    if (!buffer) {
        return tool_rc_general_error;
    }

    return tpm2_hash_common(ectx, halg, hierarchy, NULL, buffer, length, result,
        validation);
}

tool_rc tpm2_hash_file(ESYS_CONTEXT *ectx, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation) {

    if (!input) {
        return tool_rc_general_error;
    }

    return tpm2_hash_common(ectx, halg, hierarchy, input, NULL, 0, result,
        validation);
}
