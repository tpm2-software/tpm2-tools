#include <string.h>

#include <sapi/tpm20.h>

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
    int i;
    TPM2B emptyBuffer;
    TPMT_TK_HASHCHECK validation;

    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdSessionArray[1] = { &cmdAuth };
    TSS2_SYS_CMD_AUTHS cmdAuthArray = { 1, &cmdSessionArray[0] };

    nullAuth.t.size = 0;
    emptyBuffer.size = 0;

    // Set result size to 0, in case any errors occur
    result->b.size = 0;

    // Init input sessions struct
    cmdAuth.sessionHandle = TPM_RS_PW;
    cmdAuth.nonce.t.size = 0;
    *((UINT8 *) ((void *) &cmdAuth.sessionAttributes)) = 0;
    cmdAuth.hmac.t.size = 0;

    rval = Tss2_Sys_HashSequenceStart(sapi_context, 0, &nullAuth, hashAlg,
            &sequenceHandle, 0);
    if (rval != TPM_RC_SUCCESS) {
        return rval;
    }

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
    UINT8 numBuffers = 0;
    UINT32 i;
    if (length <= MAX_DIGEST_BUFFER) {
        if (tpm_hash(sapi_context, halg, length, buffer,
                result) == TPM_RC_SUCCESS)
            return 0;
        else
            return -1;
    }

    numBuffers = (length - 1) / MAX_DIGEST_BUFFER + 1;

    TPM2B_MAX_BUFFER *bufferList = (TPM2B_MAX_BUFFER *) calloc(numBuffers,
            sizeof(TPM2B_MAX_BUFFER));
    if (bufferList == NULL)
        return -2;

    for (i = 0; i < numBuffers - 1; i++) {
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
