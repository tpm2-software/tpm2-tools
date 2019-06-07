/* SPDX-License-Identifier: BSD-3-Clause */

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_error.h"
#include "tpm2_util.h"

tool_rc tpm2_readpublic(
        ESYS_CONTEXT *esysContext,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_PUBLIC **outPublic,
        TPM2B_NAME **name,
        TPM2B_NAME **qualifiedName) {

    TSS2_RC rval = Esys_ReadPublic(
            esysContext,
            objectHandle,
            shandle1,
            shandle2,
            shandle3,
            outPublic,
            name,
            qualifiedName);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ReadPublic, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_from_tpm_public(
            ESYS_CONTEXT *esysContext,
            TPM2_HANDLE tpm_handle,
            ESYS_TR optionalSession1,
            ESYS_TR optionalSession2,
            ESYS_TR optionalSession3,
            ESYS_TR *object) {

    TSS2_RC rval = Esys_TR_FromTPMPublic(
            esysContext,
            tpm_handle,
            optionalSession1,
            optionalSession2,
            optionalSession3,
            object);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_tr_deserialize(
    ESYS_CONTEXT *esys_context,
    uint8_t const *buffer,
    size_t buffer_size,
    ESYS_TR *esys_handle) {

    TSS2_RC rval = Esys_TR_Deserialize(
            esys_context,
            buffer,
            buffer_size,
            esys_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_Deserialize, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_tr_serialize(
    ESYS_CONTEXT *esys_context,
    ESYS_TR object,
    uint8_t **buffer,
    size_t *buffer_size) {

    TSS2_RC rval = Esys_TR_Serialize(
            esys_context,
            object,
            buffer,
            buffer_size);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_Serialize, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_tr_get_name(
        ESYS_CONTEXT *esysContext,
        ESYS_TR handle,
        TPM2B_NAME **name) {

    TSS2_RC rval = Esys_TR_GetName(
        esysContext,
        handle,
        name);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_GetName, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_close(
        ESYS_CONTEXT *esys_context,
        ESYS_TR *rsrc_handle) {

    TSS2_RC rval = Esys_TR_Close(
        esys_context,
        rsrc_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_Close, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_nv_readpublic(
        ESYS_CONTEXT *esysContext,
        ESYS_TR nvIndex,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_NV_PUBLIC **nvPublic,
        TPM2B_NAME **nvName) {

    TSS2_RC rval = Esys_NV_ReadPublic(
        esysContext,
        nvIndex,
        shandle1,
        shandle2,
        shandle3,
        nvPublic,
        nvName);

    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ReadPublic, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_getcap(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 propertyCount,
        TPMI_YES_NO *moreData,
        TPMS_CAPABILITY_DATA **capabilityData) {

    TSS2_RC rval =  Esys_GetCapability(
        esysContext,
        shandle1,
        shandle2,
        shandle3,
        capability,
        property,
        propertyCount,
        moreData,
        capabilityData);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ReadPublic, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_nv_read(
        ESYS_CONTEXT *esysContext,
        ESYS_TR authHandle,
        ESYS_TR nvIndex,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        UINT16 size,
        UINT16 offset,
        TPM2B_MAX_NV_BUFFER **data) {

    TSS2_RC rval = Esys_NV_Read(
        esysContext,
        authHandle,
        nvIndex,
        shandle1,
        shandle2,
        shandle3,
        size,
        offset,
        data);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_Read, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_context_save(
        ESYS_CONTEXT *esysContext,
        ESYS_TR saveHandle,
        TPMS_CONTEXT **context) {

    TSS2_RC rval = Esys_ContextSave(
            esysContext,
            saveHandle,
            context);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_ContextSave, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_context_load(
        ESYS_CONTEXT *esysContext,
        const TPMS_CONTEXT *context,
        ESYS_TR *loadedHandle) {

    TSS2_RC rval = Esys_ContextLoad(esysContext, context, loadedHandle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_ContextLoad, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_flush_context(
        ESYS_CONTEXT *esysContext,
        ESYS_TR flushHandle) {

    TSS2_RC rval = Esys_FlushContext(
        esysContext,
        flushHandle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_FlushContext, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_start_auth_session(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceCaller,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash,
    ESYS_TR *sessionHandle) {

    TSS2_RC rval = Esys_StartAuthSession(
            esysContext,
            tpmKey,
            bind,
            shandle1,
            shandle2,
            shandle3,
            nonceCaller,
            sessionType,
            symmetric,
            authHash,
            sessionHandle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_StartAuthSession, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_sess_set_attributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION flags,
    TPMA_SESSION mask) {

    TSS2_RC rval = Esys_TRSess_SetAttributes(
        esysContext,
        session,
        flags,
        mask);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TRSess_SetAttributes, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_sess_get_attributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION *flags) {

    TSS2_RC rval = Esys_TRSess_GetAttributes(
        esysContext,
        session,
        flags);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_TRSess_GetAttributes, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_restart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3) {

    TSS2_RC rval =  Esys_PolicyRestart(
        esysContext,
        sessionHandle,
        shandle1,
        shandle2,
        shandle3);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyRestart, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_get_capability(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CAP capability,
    UINT32 property,
    UINT32 propertyCount,
    TPMI_YES_NO *moreData,
    TPMS_CAPABILITY_DATA **capabilityData) {

    TSS2_RC rval = Esys_GetCapability(
        esysContext,
        shandle1,
        shandle2,
        shandle3,
        capability,
        property,
        propertyCount,
        moreData,
        capabilityData);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_GetCapability, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_create_primary(
        ESYS_CONTEXT *esysContext,
        ESYS_TR primaryHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE_CREATE *inSensitive,
        const TPM2B_PUBLIC *inPublic,
        const TPM2B_DATA *outsideInfo,
        const TPML_PCR_SELECTION *creationPCR,
        ESYS_TR *objectHandle,
        TPM2B_PUBLIC **outPublic,
        TPM2B_CREATION_DATA **creationData,
        TPM2B_DIGEST **creationHash,
        TPMT_TK_CREATION **creationTicket) {

        TSS2_RC rval = Esys_CreatePrimary(
            esysContext,
            primaryHandle,
            shandle1,
            shandle2,
            shandle3,
            inSensitive,
            inPublic,
            outsideInfo,
            creationPCR,
            objectHandle,
            outPublic,
            creationData,
            creationHash,
            creationTicket);
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Esys_CreatePrimary, rval);
            return tool_rc_from_tpm(rval);
        }

        return tool_rc_success;
}

tool_rc tpm2_pcr_read(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrSelectionIn,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION **pcrSelectionOut,
    TPML_DIGEST **pcrValues) {

    TSS2_RC rval = Esys_PCR_Read(
            esysContext,
            shandle1,
            shandle2,
            shandle3,
            pcrSelectionIn,
            pcrUpdateCounter,
            pcrSelectionOut,
            pcrValues);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PCR_Read, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_authorize(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *approvedPolicy,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *keySign,
    const TPMT_TK_VERIFIED *checkTicket) {

    TSS2_RC rval = Esys_PolicyAuthorize(
            esysContext,
            policySession,
            shandle1,
            shandle2,
            shandle3,
            approvedPolicy,
            policyRef,
            keySign,
            checkTicket);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyAuthorize, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_or(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST *pHashList) {

    TSS2_RC rval = Esys_PolicyOR(
            esysContext,
            policySession,
            shandle1,
            shandle2,
            shandle3,
            pHashList);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyAuthorize, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_pcr(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs) {

    TSS2_RC rval = Esys_PolicyPCR(
            esysContext,
            policySession,
            shandle1,
            shandle2,
            shandle3,
            pcrDigest,
            pcrs);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyPCR, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_password(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3) {

    TSS2_RC rval = Esys_PolicyPassword(
        esysContext,
        policySession,
        shandle1,
        shandle2,
        shandle3);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyPassword, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_secret(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket) {

    TSS2_RC rval = Esys_PolicySecret(
        esysContext,
        authHandle,
        policySession,
        shandle1,
        shandle2,
        shandle3,
        nonceTPM,
        cpHashA,
        policyRef,
        expiration,
        timeout,
        policyTicket);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_getdigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST **policyDigest) {

    TSS2_RC rval = Esys_PolicyGetDigest(
        esysContext,
        policySession,
        shandle1,
        shandle2,
        shandle3,
        policyDigest);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyGetDigest, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_command_code(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code) {

    TSS2_RC rval = Esys_PolicyCommandCode(
        esysContext,
        policySession,
        shandle1,
        shandle2,
        shandle3,
        code);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyCommandCode, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_locality(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMA_LOCALITY locality) {

    TSS2_RC rval = Esys_PolicyLocality(
        esysContext,
        policySession,
        shandle1,
        shandle2,
        shandle3,
        locality);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyLocality, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_policy_duplication_select(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NAME *objectName,
    const TPM2B_NAME *newParentName,
    TPMI_YES_NO includeObject) {

    TSS2_RC rval = Esys_PolicyDuplicationSelect(
        esysContext,
        policySession,
        shandle1,
        shandle2,
        shandle3,
        objectName,
        newParentName,
        includeObject);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicyDuplicationSelect, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_mu_tpm2_handle_unmarshal(
    uint8_t const   buffer[],
    size_t          size,
    size_t          *offset,
    TPM2_HANDLE     *out) {

    TSS2_RC rval = Tss2_MU_TPM2_HANDLE_Unmarshal(
        buffer,
        size,
        offset,
        out);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_MU_TPM2_HANDLE_Unmarshal, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_mu_tpmt_public_marshal(
    TPMT_PUBLIC    const *src,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset) {

    TSS2_RC rval = Tss2_MU_TPMT_PUBLIC_Marshal(
        src,
        buffer,
        buffer_size,
        offset);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_MU_TPMT_PUBLIC_Marshal, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_evictcontrol(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_DH_PERSISTENT persistentHandle,
    ESYS_TR *newObjectHandle) {

    TSS2_RC rval = Esys_EvictControl(
            esysContext,
            auth,
            objectHandle,
            shandle1,
            shandle2,
            shandle3,
            persistentHandle,
            newObjectHandle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_EvictControl, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_hash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **outHash,
    TPMT_TK_HASHCHECK **validation) {

    TSS2_RC rval = Esys_Hash(
        esysContext,
        shandle1,
        shandle2,
        shandle3,
        data,
        hashAlg,
        hierarchy,
        outHash,
        validation);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_Hash, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_hash_sequence_start(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg,
    ESYS_TR *sequenceHandle) {

    TSS2_RC rval = Esys_HashSequenceStart(
        esysContext,
        shandle1,
        shandle2,
        shandle3,
        auth,
        hashAlg,
        sequenceHandle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_HashSequenceStart, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_sequence_update(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer) {

    TSS2_RC rval = Esys_SequenceUpdate(
        esysContext,
        sequenceHandle,
        shandle1,
        shandle2,
        shandle3,
        buffer);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SequenceUpdate, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_sequence_complete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation) {

    TSS2_RC rval = Esys_SequenceComplete(
        esysContext,
        sequenceHandle,
        shandle1,
        shandle2,
        shandle3,
        buffer,
        hierarchy,
        result,
        validation);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SequenceComplete, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_tr_set_auth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_AUTH const *authValue) {

    TSS2_RC rval = Esys_TR_SetAuth(
        esysContext,
        handle,
        authValue);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_SequenceComplete, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_create(
        ESYS_CONTEXT *esysContext,
        ESYS_TR parentHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE_CREATE *inSensitive,
        const TPM2B_PUBLIC *inPublic,
        const TPM2B_DATA *outsideInfo,
        const TPML_PCR_SELECTION *creationPCR,
        TPM2B_PRIVATE **outPrivate,
        TPM2B_PUBLIC **outPublic,
        TPM2B_CREATION_DATA **creationData,
        TPM2B_DIGEST **creationHash,
        TPMT_TK_CREATION **creationTicket) {

    TSS2_RC rval = Esys_Create(
        esysContext,
        parentHandle,
        shandle1,
        shandle2,
        shandle3,
        inSensitive,
        inPublic,
        outsideInfo,
        creationPCR,
        outPrivate,
        outPublic,
        creationData,
        creationHash,
        creationTicket);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_Create, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_create_loaded(
            ESYS_CONTEXT *esysContext,
            ESYS_TR parentHandle,
            ESYS_TR shandle1,
            ESYS_TR shandle2,
            ESYS_TR shandle3,
            const TPM2B_SENSITIVE_CREATE *inSensitive,
            const TPM2B_TEMPLATE *inPublic,
            ESYS_TR *objectHandle,
            TPM2B_PRIVATE **outPrivate,
            TPM2B_PUBLIC **outPublic) {

    TSS2_RC rval = Esys_CreateLoaded(
        esysContext,
        parentHandle,
        shandle1,
        shandle2,
        shandle3,
        inSensitive,
        inPublic,
        objectHandle,
        outPrivate,
        outPublic);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_CreateLoaded, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}
