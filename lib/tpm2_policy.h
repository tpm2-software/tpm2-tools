/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_POLICY_H_
#define TPM2_POLICY_H_

#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "object.h"
#include "pcr.h"
#include "tpm2_session.h"

/**
 * Build a PCR policy via PolicyPCR.
 * @param context
 *  The Enhanced System API (ESAPI) context.
 * @param policy_session
 *  A session started with tpm2_session_new().
 * @param raw_pcrs_file
 *  The a file output from tpm2_pcrread -o option. Optional, can be NULL.
 *  If NULL, the PCR values are read via the pcr_selection value.
 * @param pcr_selections
 *  The pcr selections to use when building the pcr policy. It follows the PCR selection
 *  specifications in the man page for tpm2_listpcrs. If using a raw_pcrs_file, this spec
 *  must be the same as supplied to tpm2_listpcrs.
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_policy_build_pcr(ESYS_CONTEXT *context,
        tpm2_session *policy_session, const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections, TPM2B_DIGEST *raw_pcr_digest,
        tpm2_forwards *forwards);

/**
 * Enables a signing authority to authorize policies
 * @param ectx
 *   The Enhanced system api context
 * @param policy_session
 *   The policy session that has the policy digest to be authorized
 * @param policy_digest_path
 *   The policy digest file that needs to be authorized by signing authority
 * @param policy_qualifier
 *   The policy qualifier data that concatenates with approved policies. Can be
 *   either a path to a file or a hex string.
 * @param verifying_pubkey_name_path
 *   The name of the public key that verifies the signature of the signer
 * @param ticket_path
 *   The verification ticket generated when TPM verifies the signature
 * @return
 *   tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policyauthorize(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, const char *policy_digest_path,
        const char *policy_qualifier,
        const char *verifying_pubkey_name_path, const char *ticket_path,
        TPM2B_DIGEST *cp_hash, TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Compounds policies in an OR fashion
 *
 * @param ectx
 *   The Enhanced system api context
 * @param policy_session
 *   The policy session into which the policy digest is extended into
 * @param policy_list
 *   The list of policy policy digests
 *
 * @return
 *   tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policyor(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, TPML_DIGEST *policy_list);

/**
 * Evaluates an authorization for specific named objects.
 *
 * @param ectx
 *  The Enhanced system api context
 * @param session
 *  The policy session into which the policy digest is extended into
 * @param name_hash
 *  The name hash
 *
 * @return
 *   tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policynamehash(ESYS_CONTEXT *ectx,
    tpm2_session *session, const TPM2B_DIGEST *name_hash);

/**
 * Evaluates an authorization for object's public template data digest.
 *
 * @param ectx
 *  The Enhanced system api context
 * @param session
 *  The policy session into which the policy digest is extended into
 * @param template_hash
 *  The public template hash
 *
 * @return
 *   tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policytemplate(ESYS_CONTEXT *ectx,
    tpm2_session *session, const TPM2B_DIGEST *template_hash);

/**
 * Evaluates an authorization for object's command parameter digest.
 *
 * @param ectx
 *  The Enhanced system api context
 * @param session
 *  The policy session into which the policy digest is extended into
 * @param cphash
 *  The command parameter hash
 *
 * @return
 *   tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policycphash(ESYS_CONTEXT *ectx,
    tpm2_session *session, const TPM2B_DIGEST *cphash);

/**
 * Enables secret (password/hmac) based authorization to a policy.
 *
 * @param ectx
 *  The Enhanced system api (ESAPI) context
 * @param policy_session into which the policy digest is extended into
 *  The policy session
 * @param[in] secret_session
 *  The secret authentication data to update the policy session with.
 *  Must be a password session.
 * @param[in] handle
 *  The handle-id of the authentication object
 *
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policysecret(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, tpm2_loaded_object *auth_entity_obj,
        INT32 expiration, TPMT_TK_AUTH **policy_ticket,
        TPM2B_TIMEOUT **timeout, bool is_nonce_tpm,
        const char *policy_qualifier_path, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Retrieves the policy digest for a session via PolicyGetDigest.
 * @param context
 *  The Enhanced System API (ESAPI) context.
 * @param session
 *  The session whose digest to query.
 * @param policy_digest
 *  The retrieved digest, only valid on true returns.
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_policy_get_digest(ESYS_CONTEXT *context, tpm2_session *session,
    TPM2B_DIGEST **policy_digest, TPM2B_DIGEST *cphash,
    TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Enables a policy that requires the object's authentication passphrase be
 * provided.
 * @param ectx
 *  The Enhanced system api (ESAPI_) context.
 * @param session
 *  The policy session which is extended with PolicyPassword command code
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policypassword(ESYS_CONTEXT *ectx,
        tpm2_session *session, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Enables a policy that requires the object's authvalue be provided.
 * The authvalue can be transmitted as an HMAC
 * @param ectx
 *  The Enhanced system api (ESAPI_) context.
 * @param session
 *  The policy session which is extended with PolicyAuthValue command code
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policyauthvalue(ESYS_CONTEXT *ectx,
        tpm2_session *session, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Enables a policy authorization by virtue of verifying a signature on optional
 * TPM2 parameters data - nonceTPM, cphashA, policyRef, expiration
 * @param ectx
 *  The Enhanced system api (ESAPI) context
 * @param session
 *  The policy session which is extended with PolicySigned command code
 * @param auth_entity_obj
 *  The loaded TPM2 key object public portion used for signature verification
 * @param signature
 *  The signature of the optional TPM2 parameters
 */
tool_rc tpm2_policy_build_policysigned(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, tpm2_loaded_object *auth_entity_obj,
        TPMT_SIGNATURE *signature, INT32 expiration, TPM2B_TIMEOUT **timeout,
        TPMT_TK_AUTH **policy_ticket, const char *policy_qualifier_path,
        bool is_nonce_tpm, const char *raw_data_path,
        const char *cphash_path);

/**
 * PolicyTicket assertion enables proxy authentication for either PolicySecret
 * or PolicySigned once the specific policy is validated.
 *
 * @param ectx
 *  The Enhanced system api (ESAPI) context
 * @param session
 *  The policy session which is being extended
 * @param policy_timeout_path
 *  The file containing the timeout data generated PolicySigned/ PolicySecret
 * @param qualifier_data_path
 *  The file containing the qualifier data or policyRef
  * @param policy_ticket_path
 *  The file containing the auth ticket
 * @param auth_name_file
 *  The auth name file containing the name of the auth object
 *
 * @return     { description_of_the_return_value }
 */
tool_rc tpm2_policy_build_policyticket(ESYS_CONTEXT *ectx,
    tpm2_session *policy_session, char *policy_timeout_path,
    const char *qualifier_data_path, char *policy_ticket_path,
    const char *auth_name_file);

/**
 * Parses the policy digest algorithm for the list of policies specified
 *
 * @param str
 *  The string specifying the policy digest algorithm and list of policies
 * @param policy_list
 *  The policy list structure that records all the policies from policy list
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_policy_parse_policy_list(char *str, TPML_DIGEST *policy_list);

/**
 * Policy to restrict tpm object authorization to specific commands
 *
 * @param ectx
 *   The Enhanced system api (ESAPI_) context.
 * @param policy_session
 *   The policy session into which the policy digest is extended into
 * @param command_code
 *   The command code of the command authorized to use the object
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policycommandcode(ESYS_CONTEXT *ectx,
        tpm2_session *session, uint32_t command_code, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Policy to restrict authorization to written state of the NV Index
 *
 * @param ectx
 *   The Enhanced system api (ESAPI_) context.
 * @param policy_session
 *   The policy session into which the policy digest is extended into
 * @param written_set
 *   SET/ CLEAR TPMI_YES_NO value of the expected written state of NV index
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policynvwritten(ESYS_CONTEXT *ectx,
        tpm2_session *session, TPMI_YES_NO written_set, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Policy to restrict tpm object authorization to specific locality
 *
 * @param ectx
 *   The Enhanced system api (ESAPI_) context.
 * @param policy_session
 *   The policy session into which the policy digest is extended into
 * @param locality
 *   The locality of the command authorized to use the object
 * @return
 *   A tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policylocality(ESYS_CONTEXT *ectx,
        tpm2_session *session, TPMA_LOCALITY locality, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm);

/**
 * Policy to restrict tpm object authorization to specific duplication target
 *
 * @param ectx
 *   The Enhanced system api (ESAPI_) context.
 * @param policy_session
 *   The policy session into which the policy digest is extended into
 * @param obj_name_path
 *   The name of the tpm object to be duplicated
 * @param new_parent_name_path
 *   The name of the new parent to which the object is duplicated
 * @param is_include_obj
 *   the flag indicating whether object name is included in policyDigest
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policyduplicationselect(ESYS_CONTEXT *ectx,
        tpm2_session *session, const char *obj_name_path,
        const char *new_parent_name_path, TPMI_YES_NO is_include_obj);

/**
 * Policy tools need to:
 *  - get the policy digest
 *  - print the policy digest
 *  - optionally save the digest to a file
 *  This routine serves a common helper so all policy tools
 *  behave in the same way.
 * @param ectx
 *  The Enhanced system api (ESAPI_) context.
 * @param session
 *  The policy session to get the digest of.
 * @param save_path
 *  The path to optionally save the digest too.
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_policy_tool_finish(ESYS_CONTEXT *ectx, tpm2_session *session,
        const char *save_path);

/** Sets a TPM2B_DIGEST from a file if present or a hex string.
 *
 * @param auth_policy
 *  Either a file path or a hex string. A NULL pointer causes out_policy to be memset
 *  to 0.
 * @param out_policy
 *  The set policy
 * @return
 *  tool_rc_success on success, or any tool_rc failure on failure.
 */
tool_rc tpm2_policy_set_digest(const char *auth_policy, TPM2B_DIGEST *out_policy);

#endif /* TPM2_POLICY_H_ */
