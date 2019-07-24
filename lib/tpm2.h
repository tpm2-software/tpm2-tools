/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_H_
#define LIB_TPM2_H_

#include <tss2/tss2_esys.h>

#include "object.h"
#include "tpm2_error.h"

tool_rc tpm2_from_tpm_public(
            ESYS_CONTEXT *esysContext,
            TPM2_HANDLE tpm_handle,
            ESYS_TR optionalSession1,
            ESYS_TR optionalSession2,
            ESYS_TR optionalSession3,
            ESYS_TR *object);

tool_rc tpm2_close(
        ESYS_CONTEXT *esys_context,
        ESYS_TR *rsrc_handle);

tool_rc tpm2_tr_deserialize(
    ESYS_CONTEXT *esys_context,
    uint8_t const *buffer,
    size_t buffer_size,
    ESYS_TR *esys_handle);

tool_rc tpm2_tr_serialize(
    ESYS_CONTEXT *esys_context,
    ESYS_TR object,
    uint8_t **buffer,
    size_t *buffer_size);

tool_rc tpm2_nv_readpublic(
        ESYS_CONTEXT *esysContext,
        ESYS_TR nvIndex,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_NV_PUBLIC **nvPublic,
        TPM2B_NAME **nvName);

tool_rc tpm2_readpublic(ESYS_CONTEXT *esysContext,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_PUBLIC **outPublic,
        TPM2B_NAME **name,
        TPM2B_NAME **qualifiedName);

tool_rc tpm2_getcap(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 propertyCount,
        TPMI_YES_NO *moreData,
        TPMS_CAPABILITY_DATA **capabilityData);

tool_rc tpm2_nv_read(
        ESYS_CONTEXT *esysContext,
        ESYS_TR authHandle,
        ESYS_TR nvIndex,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        UINT16 size,
        UINT16 offset,
        TPM2B_MAX_NV_BUFFER **data);

tool_rc tpm2_context_save(
        ESYS_CONTEXT *esysContext,
        ESYS_TR saveHandle,
        TPMS_CONTEXT **context);

tool_rc tpm2_context_load(
        ESYS_CONTEXT *esysContext,
        const TPMS_CONTEXT *context,
        ESYS_TR *loadedHandle);

tool_rc tpm2_flush_context(
        ESYS_CONTEXT *esysContext,
        ESYS_TR flushHandle);

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
    ESYS_TR *sessionHandle);

tool_rc tpm2_sess_set_attributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION flags,
    TPMA_SESSION mask);

tool_rc tpm2_sess_get_attributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION *flags);

tool_rc tpm2_policy_restart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_get_capability(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CAP capability,
    UINT32 property,
    UINT32 propertyCount,
    TPMI_YES_NO *moreData,
    TPMS_CAPABILITY_DATA **capabilityData);

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
        TPMT_TK_CREATION **creationTicket);

tool_rc tpm2_pcr_read(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrSelectionIn,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION **pcrSelectionOut,
    TPML_DIGEST **pcrValues);

tool_rc tpm2_policy_authorize(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *approvedPolicy,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *keySign,
    const TPMT_TK_VERIFIED *checkTicket);

tool_rc tpm2_policy_or(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST *pHashList);

tool_rc tpm2_policy_pcr(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs);

tool_rc tpm2_policy_password(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_policy_secret(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_entity_obj,
    ESYS_TR policySession);

tool_rc tpm2_policy_getdigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST **policyDigest);

tool_rc tpm2_policy_command_code(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code);

tool_rc tpm2_policy_locality(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMA_LOCALITY locality);

tool_rc tpm2_policy_duplication_select(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NAME *objectName,
    const TPM2B_NAME *newParentName,
    TPMI_YES_NO includeObject);

tool_rc tpm2_tr_get_name(
        ESYS_CONTEXT *esysContext,
        ESYS_TR handle,
        TPM2B_NAME **name);

tool_rc tpm2_mu_tpm2_handle_unmarshal(
    uint8_t const   buffer[],
    size_t          size,
    size_t          *offset,
    TPM2_HANDLE     *out);

tool_rc tpm2_mu_tpmt_public_marshal(
    TPMT_PUBLIC    const *src,
    uint8_t        buffer[],
    size_t         buffer_size,
    size_t         *offset);

tool_rc tpm2_evictcontrol(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    tpm2_loaded_object *to_persist_key_obj,
    TPMI_DH_PERSISTENT persistentHandle,
    ESYS_TR *newObjectHandle);

tool_rc tpm2_hash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **outHash,
    TPMT_TK_HASHCHECK **validation);

tool_rc tpm2_hash_sequence_start(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg,
    ESYS_TR *sequenceHandle);

tool_rc tpm2_sequence_update(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

tool_rc tpm2_sequence_complete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation);

tool_rc tpm2_tr_set_auth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_AUTH const *authValue);

tool_rc tpm2_activatecredential(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *activatehandle,
        tpm2_loaded_object *keyhandle,
        const TPM2B_ID_OBJECT *credentialBlob,
        const TPM2B_ENCRYPTED_SECRET *secret,
        TPM2B_DIGEST **certInfo);

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
    TPMT_TK_CREATION **creationTicket);

tool_rc tpm2_create_loaded(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *parent_obj,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_TEMPLATE *inPublic,
    ESYS_TR *objectHandle,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic);

tool_rc tpm2_object_change_auth(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *parent_object,
        tpm2_loaded_object *object,
        const TPM2B_AUTH *newAuth,
        TPM2B_PRIVATE **outPrivate);

tool_rc tpm2_nv_change_auth(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *nv,
        const TPM2B_AUTH *newAuth);

tool_rc tpm2_hierarchy_change_auth(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *hierarchy,
        const TPM2B_AUTH *newAuth);

tool_rc tpm2_certify(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *certifiedkey_obj,
    tpm2_loaded_object *signingkey_obj,
    TPM2B_DATA *qualifying_data,
    TPMT_SIG_SCHEME *scheme,
    TPM2B_ATTEST **certify_info,
    TPMT_SIGNATURE **signature);

tool_rc tpm2_rsa_decrypt(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *keyobj,
    const TPM2B_PUBLIC_KEY_RSA *cipherText,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label,
    TPM2B_PUBLIC_KEY_RSA **message);

tool_rc tpm2_load(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *parentobj,
    const TPM2B_PRIVATE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    ESYS_TR *objectHandle);

tool_rc tpm2_clear(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy);

tool_rc tpm2_clearcontrol(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy,
    TPMI_YES_NO disable_clear);

tool_rc tpm2_dictionarylockout(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy,
    bool clear_lockout,
    bool setup_parameters,
    UINT32 max_tries,
    UINT32 recovery_time,
    UINT32 lockout_recovery_time);

tool_rc tpm2_duplicate(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *duplicable_key,
    ESYS_TR new_parent_handle,
    const TPM2B_DATA *in_key,
    const TPMT_SYM_DEF_OBJECT *sym_alg,
    TPM2B_DATA **out_key,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **encrypted_seed);

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
    unsigned *version);

tool_rc tpm2_hierarchycontrol(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy,
    TPMI_RH_ENABLES enable,
    TPMI_YES_NO state);

tool_rc tpm2_hmac(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *hmac_key_obj,
    TPMI_ALG_HASH halg,
    const TPM2B_MAX_BUFFER *input_buffer,
    TPM2B_DIGEST **out_hmac);

tool_rc tpm2_hmac_start(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *hmac_key_obj,
    TPMI_ALG_HASH halg,
    ESYS_TR *sequenceHandle);

tool_rc tpm2_hmac_sequenceupdate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    tpm2_loaded_object *hmac_key_obj,
    const TPM2B_MAX_BUFFER *input_buffer);

tool_rc tpm2_hmac_sequencecomplete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    tpm2_loaded_object *hmac_key_obj,
    const TPM2B_MAX_BUFFER *input_buffer,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation);

tool_rc tpm2_import(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *parent_obj,
    const TPM2B_DATA *encryptionKey,
    const TPM2B_PUBLIC *objectPublic,
    const TPM2B_PRIVATE *duplicate,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_PRIVATE **outPrivate);

tool_rc tpm2_nv_definespace(
        ESYS_CONTEXT *esysContext,
        tpm2_loaded_object *auth_hierarchy_obj,
        const TPM2B_AUTH *auth,
        const TPM2B_NV_PUBLIC *publicInfo);

tool_rc tpm2_nv_increment(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    TPM2_HANDLE nv_index);

tool_rc tpm2_nvreadlock(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    TPM2_HANDLE nv_index);

tool_rc tpm2_nvrelease(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    TPM2_HANDLE nv_index);

tool_rc tpm2_nvwrite(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    TPM2_HANDLE nvindex,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset);

tool_rc tpm2_pcr_allocate(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *auth_hierarchy_obj,
    const TPML_PCR_SELECTION *pcrAllocation);

tool_rc tpm2_sign(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *signingkey_obj,
    TPM2B_DIGEST *digest,
    TPMT_SIG_SCHEME *inScheme,
    TPMT_TK_HASHCHECK *validation,
    TPMT_SIGNATURE **signature);

tool_rc tpm2_quote(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *quote_obj,
    TPMT_SIG_SCHEME *inScheme,
    TPM2B_DATA *qualifyingData,
    TPML_PCR_SELECTION *PCRselect,
    TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature);

tool_rc tpm2_unseal(
    ESYS_CONTEXT *esysContext,
    tpm2_loaded_object *sealkey_obj,
    TPM2B_SENSITIVE_DATA **outData);

#endif /* LIB_TPM2_H_ */
