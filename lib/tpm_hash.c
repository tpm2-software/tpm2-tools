#include <string.h>

#include <sapi/tpm20.h>

#include "tpm2_util.h"

UINT32 tpm_hash(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hashAlg,
        UINT16 size, BYTE *data, TPM2B_DIGEST *result) {
    TPM2B_MAX_BUFFER dataSizedBuffer;

    dataSizedBuffer.t.size = size;
    memcpy(dataSizedBuffer.t.buffer, data, size);
    return Tss2_Sys_Hash(sapi_context, 0, &dataSizedBuffer, hashAlg,
            TPM_RH_NULL, result, 0, 0);
}

static TPM_RC hash_sequence_ex(TSS2_SYS_CONTEXT *sapi_context,

    TPMI_ALG_HASH hashAlg, UINT32 numBuffers, TPM2B_MAX_BUFFER *bufferList,
    TPM2B_DIGEST *result) {
    TPM_RC rval;
    TPM2B_AUTH nullAuth;
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B emptyBuffer;
    TPMT_TK_HASHCHECK validation;

    TPMS_AUTH_COMMAND cmdAuth = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    };
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    nullAuth.t.size = 0;
    emptyBuffer.size = 0;

    // Set result size to 0, in case any errors occur
    result->b.size = 0;

    // Init input sessions struct

    rval = Tss2_Sys_HashSequenceStart(sapi_context, 0, &nullAuth, hashAlg,
            &sequenceHandle, 0);
    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }

    unsigned i;
    for (i = 0; i < numBuffers; i++) {
        rval = Tss2_Sys_SequenceUpdate(sapi_context, sequenceHandle,
                &cmdAuthArray, &bufferList[i], 0);

        if (rval != TPM_RC_SUCCESS) {
            return rval;
        }
    }

    rval = Tss2_Sys_SequenceComplete(sapi_context, sequenceHandle,
            &cmdAuthArray, (TPM2B_MAX_BUFFER *) &emptyBuffer,
            TPM_RH_PLATFORM, result, &validation, 0);

    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }

    return rval;
}

int tpm_hash_compute_data(TSS2_SYS_CONTEXT *sapi_context, BYTE *buffer,
        UINT16 length, TPMI_ALG_HASH halg, TPM2B_DIGEST *result) {

    if (length <= MAX_DIGEST_BUFFER) {
        if (tpm_hash(sapi_context, halg, length, buffer,
                result) == TPM_RC_SUCCESS)
            return 0;
        else
            return -1;
    }

    UINT8 numBuffers = (length - 1) / MAX_DIGEST_BUFFER + 1;

    TPM2B_MAX_BUFFER *bufferList = (TPM2B_MAX_BUFFER *) calloc(numBuffers,
            sizeof(TPM2B_MAX_BUFFER));
    if (bufferList == NULL)
        return -2;

    UINT32 i;
    for (i = 0; i < (UINT32)(numBuffers - 1); i++) {
        bufferList[i].t.size = MAX_DIGEST_BUFFER;
        memcpy(bufferList[i].t.buffer, buffer + i * MAX_DIGEST_BUFFER,
                MAX_DIGEST_BUFFER);
    }
    bufferList[i].t.size = length - i * MAX_DIGEST_BUFFER;
    memcpy(bufferList[i].t.buffer, buffer + i * MAX_DIGEST_BUFFER,
            bufferList[i].t.size);

    TPM_RC rval = hash_sequence_ex(sapi_context, halg, numBuffers, bufferList, result);
    free(bufferList);
    return rval == TPM_RC_SUCCESS ? 0 : -3;
}

//
// This function does a hash on an array of data strings and re-uses syscontext
//
UINT32 tpm_hash_sequence(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hash_alg,
        size_t num_buffers, TPM2B_DIGEST *buffer_list, TPM2B_DIGEST *result) {

    TPM2B_AUTH null_auth = { .t.size = 0 };
    TPMI_DH_OBJECT sequence_handle;
    UINT32 rval = Tss2_Sys_HashSequenceStart(sapi_context, 0, &null_auth,hash_alg,
                        &sequence_handle, 0);
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

    TPMT_TK_HASHCHECK validation;
    TPM2B empty_buffer = { .size = 0 };
    return Tss2_Sys_SequenceComplete(sapi_context, sequence_handle, &cmd_auth_array,
                (TPM2B_MAX_BUFFER *) &empty_buffer, TPM_RH_PLATFORM, result,
                &validation, 0);
}
