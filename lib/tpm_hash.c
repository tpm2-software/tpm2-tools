#include <errno.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "files.h"
#include "tpm_hash.h"
#include "tpm2_util.h"

#define TSS2_APP_HASH_RC_FAILED (0x1 + 0x100 + TSS2_APP_ERROR_LEVEL)

TPM_RC tpm_hash_compute_data(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST *result, TPMT_TK_HASHCHECK *validation) {

    FILE *mem = fmemopen(buffer, length, "rb");
    if (!mem) {
        LOG_ERR("Error converting buffer to memory stream: %s",
                strerror(errno));
        return TSS2_APP_HASH_RC_FAILED;
    }

    return tpm_hash_file(sapi_context, halg, hierarchy, mem, result, validation);
}

TPM_RC tpm_hash_sequence(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hash_alg,
        TPMI_RH_HIERARCHY hierarchy, size_t num_buffers,
        TPM2B_DIGEST *buffer_list, TPM2B_DIGEST *result,
        TPMT_TK_HASHCHECK *validation) {

    TPM2B_AUTH null_auth = { .t.size = 0 };
    TPMI_DH_OBJECT sequence_handle;
    UINT32 rval = Tss2_Sys_HashSequenceStart(sapi_context, 0, &null_auth,
            hash_alg, &sequence_handle, 0);
    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }

    TPMS_AUTH_COMMAND cmd_auth = TPMS_AUTH_COMMAND_INIT(TPM_RS_PW);
    TPMS_AUTH_COMMAND *cmd_session_array[1] = { &cmd_auth };
    TSS2_SYS_CMD_AUTHS cmd_auth_array = { 1, &cmd_session_array[0] };
    unsigned i;
    for (i = 0; i < num_buffers; i++) {
        rval = Tss2_Sys_SequenceUpdate(sapi_context, sequence_handle,
                &cmd_auth_array, (TPM2B_MAX_BUFFER *) &buffer_list[i], 0);

        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }
    }

    TPM2B_MAX_BUFFER empty_buffer = TPM2B_EMPTY_INIT;
    return Tss2_Sys_SequenceComplete(sapi_context, sequence_handle,
            &cmd_auth_array, &empty_buffer, hierarchy,
            result, validation, NULL);
}

TPM_RC tpm_hash_file(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST *result,
        TPMT_TK_HASHCHECK *validation) {

    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;
    TPMI_DH_OBJECT sequenceHandle;

    TPMS_AUTH_COMMAND cmdAuth = { .sessionHandle = TPM_RS_PW, .nonce =
            TPM2B_EMPTY_INIT, .hmac = TPM2B_EMPTY_INIT, .sessionAttributes =
            SESSION_ATTRIBUTES_INIT(0), };
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    unsigned long file_size = 0;

    /* Suppress error reporting with NULL path */
    bool res = files_get_file_size(input, &file_size, NULL);

    /* If we can get the file size and its less than 1024, just do it in one hash invocation */
    if (res && file_size <= MAX_DIGEST_BUFFER) {

        TPM2B_MAX_BUFFER buffer = { .t = { .size = file_size }, };

        res = files_read_bytes(input, buffer.t.buffer, buffer.t.size);
        if (!res) {
            LOG_ERR("Error reading input file!");
            return TSS2_APP_HASH_RC_FAILED;
        }

        return Tss2_Sys_Hash(sapi_context, NULL, &buffer, halg,
            hierarchy, result, validation, NULL);
    }

    /*
     * Size is either unkown because the FILE * is a fifo, or it's too big
     * to do in a single hash call. Based on the size figure out the chunks
     * to loop over, if possible. This way we can call Complete with data.
     */
    TPM_RC rval = Tss2_Sys_HashSequenceStart(sapi_context, NULL, &nullAuth,
            halg, &sequenceHandle, NULL);
    if (rval != TPM_RC_SUCCESS) {
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

        size_t bytes_read = fread(data.t.buffer, 1,
                BUFFER_SIZE(typeof(data), buffer), input);
        if (ferror(input)) {
            LOG_ERR("Error reading from input file");
            return TSS2_APP_HASH_RC_FAILED;
        }

        data.t.size = bytes_read;

        /* if data was read, update the sequence */
        rval = Tss2_Sys_SequenceUpdate(sapi_context, sequenceHandle,
                &cmdAuthArray, &data, NULL);
        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }

        if (use_left) {
            left -= bytes_read;
            if (left <= MAX_DIGEST_BUFFER) {
                done = true;
                continue;
            }
        } else if (feof(input)) {
            done = true;
        }
    } /* end file read/hash update loop */

    if (use_left) {
        data.t.size = left;
        bool res = files_read_bytes(input, data.t.buffer, left);
        if (!res) {
            LOG_ERR("Error reading from input file.");
            return TSS2_APP_HASH_RC_FAILED;
        }
    } else {
        data.t.size = 0;
    }

    return Tss2_Sys_SequenceComplete(sapi_context, sequenceHandle,
            &cmdAuthArray, &data, hierarchy, result, validation,
            NULL);
}
