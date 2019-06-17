/* SPDX-License-Identifier: BSD-3-Clause */

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_auth_util.h"
#include "tpm2_error.h"

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
    tpm2_loaded_object *auth_entity_obj,
    ESYS_TR policySession) {

    const TPM2B_NONCE *nonceTPM = NULL;
    const TPM2B_DIGEST *cpHashA = NULL;
    const TPM2B_NONCE *policyRef = NULL;
    INT32 expiration = 0;
    TPM2B_TIMEOUT **timeout = NULL;
    TPMT_TK_AUTH **policyTicket = NULL;

    ESYS_TR auth_entity_obj_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, auth_entity_obj->tr_handle,
                        auth_entity_obj->session, &auth_entity_obj_session_handle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get auth entity obj session");
        return rc;
    }

    TSS2_RC rval = Esys_PolicySecret(
        esysContext,
        auth_entity_obj->tr_handle,
        policySession,
        auth_entity_obj_session_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
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
    tpm2_loaded_object *auth_hierarchy_obj,
    tpm2_loaded_object *to_persist_key_obj,
    TPMI_DH_PERSISTENT persistentHandle,
    ESYS_TR *newObjectHandle) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        auth_hierarchy_obj->tr_handle, auth_hierarchy_obj->session, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_EvictControl(
            esysContext,
            auth_hierarchy_obj->tr_handle,
            to_persist_key_obj->tr_handle,
            shandle1,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
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

tool_rc tpm2_activatecredential(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *activatehandleobj,
        tpm2_loaded_object *keyhandleobj,
        const TPM2B_ID_OBJECT *credentialBlob,
        const TPM2B_ENCRYPTED_SECRET *secret,
        TPM2B_DIGEST **certInfo) {

    ESYS_TR keyobj_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(
                        esysContext,
                        keyhandleobj->tr_handle,
                        keyhandleobj->session,
                        &keyobj_session_handle); //shandle1
    if (rc != tool_rc_success) {
        return rc;
    }

    ESYS_TR activateobj_session_handle = ESYS_TR_NONE;
    rc = tpm2_auth_util_get_shandle(
                esysContext,
                activatehandleobj->tr_handle,
                activatehandleobj->session,
                &activateobj_session_handle); //shandle2
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_ActivateCredential(
                    esysContext,
                    activatehandleobj->tr_handle,
                    keyhandleobj->tr_handle,
                    activateobj_session_handle,
                    keyobj_session_handle,
                    ESYS_TR_NONE,
                    credentialBlob,
                    secret,
                    certInfo);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ActivateCredential, rval);
        rc = tool_rc_from_tpm(rval);
        return rc;
    }

    return tool_rc_success;
}

tool_rc tpm2_create(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *parent_obj,
        const TPM2B_SENSITIVE_CREATE *inSensitive,
        const TPM2B_PUBLIC *inPublic,
        const TPM2B_DATA *outsideInfo,
        const TPML_PCR_SELECTION *creationPCR,
        TPM2B_PRIVATE **outPrivate,
        TPM2B_PUBLIC **outPublic,
        TPM2B_CREATION_DATA **creationData,
        TPM2B_DIGEST **creationHash,
        TPMT_TK_CREATION **creationTicket) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
                            parent_obj->tr_handle,
                            parent_obj->session, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_Create(
        esysContext,
        parent_obj->tr_handle,
        shandle1,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
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
            tpm2_loaded_object *parent_obj,
            const TPM2B_SENSITIVE_CREATE *inSensitive,
            const TPM2B_TEMPLATE *inPublic,
            ESYS_TR *objectHandle,
            TPM2B_PRIVATE **outPrivate,
            TPM2B_PUBLIC **outPublic) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
                            parent_obj->tr_handle,
                            parent_obj->session, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_CreateLoaded(
        esysContext,
        parent_obj->tr_handle,
        shandle1,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
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

tool_rc tpm2_object_change_auth(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *parent_object,
        tpm2_loaded_object *object,
        const TPM2B_AUTH *newAuth,
        TPM2B_PRIVATE **outPrivate) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
                            object->tr_handle,
                            object->session, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_ObjectChangeAuth(esysContext,
                        object->tr_handle,
                        parent_object->tr_handle,
                        shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                        newAuth, outPrivate);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ObjectChangeAuth, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_nv_change_auth(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *nv,
        const TPM2B_AUTH *newAuth) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
                            nv->tr_handle,
                            nv->session, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_NV_ChangeAuth(esysContext,
                nv->tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE, newAuth);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ChangeAuth, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_hierarchy_change_auth(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *hierarchy,
        const TPM2B_AUTH *newAuth) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
                            hierarchy->tr_handle,
                            hierarchy->session, &shandle1);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_HierarchyChangeAuth(esysContext,
                hierarchy->tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE, newAuth);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_HierarchyChangeAuth, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_certify(
    ESYS_CONTEXT *ectx,
    tpm2_loaded_object *certifiedkey_obj,
    tpm2_loaded_object *signingkey_obj,
    TPM2B_DATA *qualifying_data,
    TPMT_SIG_SCHEME *scheme,
    TPM2B_ATTEST **certify_info,
    TPMT_SIGNATURE **signature) {

    ESYS_TR certifiedkey_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(ectx, certifiedkey_obj->tr_handle,
        certifiedkey_obj->session, &certifiedkey_session_handle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get session handle for TPM object");
        return rc;
    }

    ESYS_TR signingkey_session_handle = ESYS_TR_NONE;
    rc = tpm2_auth_util_get_shandle(ectx,
                            signingkey_obj->tr_handle,
                            signingkey_obj->session, &signingkey_session_handle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get session handle for key");
        return rc;
    }

    TSS2_RC rval = Esys_Certify(
                    ectx,
                    certifiedkey_obj->tr_handle,
                    signingkey_obj->tr_handle,
                    certifiedkey_session_handle,
                    signingkey_session_handle,
                    ESYS_TR_NONE,
                    qualifying_data,
                    scheme,
                    certify_info,
                    signature);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Eys_Certify, rval);
        rc = tool_rc_from_tpm(rval);
        return rc;
    }

    return tool_rc_success;
}

tool_rc tpm2_rsa_decrypt(
    ESYS_CONTEXT *ectx,
    tpm2_loaded_object *keyobj,
    const TPM2B_PUBLIC_KEY_RSA *cipher_text,
    const TPMT_RSA_DECRYPT *scheme,
    const TPM2B_DATA *label,
    TPM2B_PUBLIC_KEY_RSA **message) {

    ESYS_TR keyobj_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(ectx,
                            keyobj->tr_handle,
                            keyobj->session, &keyobj_session_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_RSA_Decrypt(
                    ectx, keyobj->tr_handle,
                    keyobj_session_handle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    cipher_text,
                    scheme,
                    label,
                    message);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_RSA_Decrypt, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_load(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *parentobj,
    const TPM2B_PRIVATE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    ESYS_TR *objectHandle) {

    ESYS_TR parent_object_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, parentobj->tr_handle,
                            parentobj->session, &parent_object_session_handle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get parent object session handle");
        return rc;
    }

    TSS2_RC rval = Esys_Load(
                    esysContext,
                    parentobj->tr_handle,
                    parent_object_session_handle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    inPrivate,
                    inPublic,
                    objectHandle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Eys_Load, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_clear(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        auth_hierarchy->tr_handle, auth_hierarchy->session, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get shandle for hierarchy");
        return rc;
    }

    TSS2_RC rval = Esys_Clear(
                    esysContext,
                    auth_hierarchy->tr_handle,
                    shandle1,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Esys_Clear, rval);
        return tool_rc_from_tpm(rval);
    }
    return tool_rc_success;
}

tool_rc tpm2_clearcontrol(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy,
    TPMI_YES_NO disable_clear) {

    ESYS_TR shandle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        auth_hierarchy->tr_handle, auth_hierarchy->session, &shandle);
    if (rc != tool_rc_success) {
        return rc;
    }

    TSS2_RC rval = Esys_ClearControl(
                    esysContext,
                    auth_hierarchy->tr_handle,
                    shandle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    disable_clear);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Esys_ClearControl, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_dictionarylockout(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy,
    bool clear_lockout,
    bool setup_parameters,
    UINT32 max_tries,
    UINT32 recovery_time,
    UINT32 lockout_recovery_time) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        auth_hierarchy->tr_handle,auth_hierarchy->session, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Couldn't get shandle for lockout hierarchy");
        return rc;
    }

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * precede parameters setup.
     */
    TPM2_RC rval;
    if (clear_lockout) {
        LOG_INFO("Resetting dictionary lockout state.");
        rval = Esys_DictionaryAttackLockReset(
                esysContext,
                auth_hierarchy->tr_handle,
                shandle1,
                ESYS_TR_NONE,
                ESYS_TR_NONE);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_DictionaryAttackLockReset, rval);
            return tool_rc_from_tpm(rval);
        }
    }

    if (setup_parameters) {
        LOG_INFO("Setting up Dictionary Lockout parameters.");
        rval = Esys_DictionaryAttackParameters(
                esysContext,
                auth_hierarchy->tr_handle,
                shandle1,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                max_tries,
                recovery_time,
                lockout_recovery_time);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_DictionaryAttackParameters, rval);
            return tool_rc_from_tpm(rval);
        }
    }

    return tool_rc_success;
}

tool_rc tpm2_duplicate(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *duplicable_key,
    ESYS_TR new_parent_handle,
    const TPM2B_DATA *in_key,
    const TPMT_SYM_DEF_OBJECT *sym_alg,
    TPM2B_DATA **out_key,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **encrypted_seed) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        duplicable_key->tr_handle, duplicable_key->session, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get shandle");
        return rc;
    }

    TSS2_RC rval = Esys_Duplicate(
                        esysContext,
                        duplicable_key->tr_handle,
                        new_parent_handle,
                        shandle1,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        in_key,
                        sym_alg,
                        out_key,
                        duplicate,
                        encrypted_seed);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Duplicate, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_encryptdecrypt(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *encryption_key_obj,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *iv_in,
    const TPM2B_MAX_BUFFER *input_data,
    TPM2B_MAX_BUFFER **output_data,
    TPM2B_IV **iv_out,
    ESYS_TR shandle1,
    unsigned *version) {


    TSS2_RC rval = Esys_EncryptDecrypt2(
                    esysContext,
                    encryption_key_obj->tr_handle,
                    shandle1,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    input_data,
                    decrypt,
                    mode,
                    iv_in,
                    output_data,
                    iv_out);
    if (tpm2_error_get(rval) == TPM2_RC_COMMAND_CODE) {
        *version = 1;
        rval = Esys_EncryptDecrypt(
                esysContext,
                encryption_key_obj->tr_handle,
                shandle1,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                decrypt,
                mode,
                iv_in,
                input_data,
                output_data,
                iv_out);
    }

    if (tpm2_error_get(rval) == TPM2_RC_COMMAND_CODE) {
        if (*version == 2) {
            LOG_PERR(Esys_EncryptDecrypt2, rval);
        } else {
            LOG_PERR(Esys_EncryptDecrypt, rval);
        }
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_hmac(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *hmac_key_obj,
    const TPM2B_MAX_BUFFER *input_buffer,
    TPM2B_DIGEST **out_hmac) {

    ESYS_TR hmac_key_obj_shandle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, hmac_key_obj->tr_handle,
                            hmac_key_obj->session, &hmac_key_obj_shandle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get hmac_key_obj_shandle");
        return rc;
    }

    TPM2_RC rval = Esys_HMAC(
                    esysContext,
                    hmac_key_obj->tr_handle,
                    hmac_key_obj_shandle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    input_buffer,
                    TPM2_ALG_NULL,
                    out_hmac);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_HMAC, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}


tool_rc tpm2_hmac_start(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *hmac_key_obj,
    ESYS_TR *sequenceHandle) {

    ESYS_TR hmac_key_obj_shandle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, hmac_key_obj->tr_handle,
                            hmac_key_obj->session, &hmac_key_obj_shandle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get hmac_key_obj_shandle");
        return rc;
    }

    TPM2B_AUTH null_auth = { .size = 0 };
    TPM2_RC rval = Esys_HMAC_Start(
                    esysContext,
                    hmac_key_obj->tr_handle,
                    hmac_key_obj_shandle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &null_auth,
                    TPM2_ALG_NULL,
                    sequenceHandle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_HMAC, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_hmac_sequenceupdate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    tpm2_loaded_object *hmac_key_obj,
    const TPM2B_MAX_BUFFER *input_buffer) {

    ESYS_TR hmac_key_obj_shandle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, hmac_key_obj->tr_handle,
                            hmac_key_obj->session, &hmac_key_obj_shandle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get hmac_key_obj_shandle");
        return rc;
    }

    TPM2_RC rval = Esys_SequenceUpdate(
                    esysContext,
                    sequenceHandle,
                    hmac_key_obj_shandle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    input_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_HMAC, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_hmac_sequencecomplete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    tpm2_loaded_object *hmac_key_obj,
    const TPM2B_MAX_BUFFER *input_buffer,
    TPM2B_DIGEST **result) {

    ESYS_TR hmac_key_obj_shandle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, hmac_key_obj->tr_handle,
                            hmac_key_obj->session, &hmac_key_obj_shandle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get hmac_key_obj_shandle");
        return rc;
    }

    TPM2_RC rval = Esys_SequenceComplete(
                    esysContext,
                    sequenceHandle,
                    hmac_key_obj_shandle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    input_buffer,
                    TPM2_RH_NULL,
                    result,
                    NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_HMAC, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_import(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *parent_obj,
    const TPM2B_DATA *encryptionKey,
    const TPM2B_PUBLIC *objectPublic,
    const TPM2B_PRIVATE *duplicate,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_PRIVATE **outPrivate) {

    ESYS_TR parentobj_shandle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext, parent_obj->tr_handle,
                            parent_obj->session, &parentobj_shandle);
    if (rc != tool_rc_success) {
        LOG_ERR("Couldn't get shandle for phandle");
        return rc;
    }

    TPM2_RC rval = Esys_Import(
                    esysContext,
                    parent_obj->tr_handle,
                    parentobj_shandle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    encryptionKey,
                    objectPublic,
                    duplicate,
                    inSymSeed,
                    symmetricAlg,
                    outPrivate);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_HMAC, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_nv_definespace(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *auth_hierarchy_obj,
        const TPM2B_AUTH *auth,
        const TPM2B_NV_PUBLIC *publicInfo) {

    ESYS_TR shandle1 = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        auth_hierarchy_obj->tr_handle, auth_hierarchy_obj->session, &shandle1);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get shandle");
        return rc;
    }

    ESYS_TR nvHandle;
    TSS2_RC rval = Esys_NV_DefineSpace(
                    esysContext,
                    auth_hierarchy_obj->tr_handle,
                    shandle1,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    auth,
                    publicInfo,
                    &nvHandle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to define NV area at index 0x%X", publicInfo->nvPublic.nvIndex);
        LOG_PERR(Esys_NV_DefineSpace, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_nv_increment(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    TPM2_HANDLE nv_index) {

    ESYS_TR auth_hierarchy_obj_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esysContext,
        auth_hierarchy_obj->tr_handle, auth_hierarchy_obj->session,
        &auth_hierarchy_obj_session_handle);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to get shandle");
        return rc;
    }

    // Convert TPM2_HANDLE ctx.nv_index to an ESYS_TR
    ESYS_TR esys_tr_nv_index;
    TSS2_RC rval = Esys_TR_FromTPMPublic(
                    esysContext,
                    nv_index,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &esys_tr_nv_index);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return tool_rc_from_tpm(rval);
    }

    rval = Esys_NV_Increment(
            esysContext,
            auth_hierarchy_obj->tr_handle,
            esys_tr_nv_index,
            auth_hierarchy_obj_session_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}
