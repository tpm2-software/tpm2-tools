/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_POLICY_H_
#define TPM2_POLICY_H_

#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "tpm2_session.h"

/**
 * Build a PCR policy via PolicyPCR.
 * @param context
 *  The Enhanced System API (ESAPI) context.
 * @param policy_session
 *  A session started with tpm2_session_new().
 * @param raw_pcrs_file
 *  The a file output from tpm2_pcrlist -o option. Optional, can be NULL.
 *  If NULL, the PCR values are read via the pcr_selection value.
 * @param pcr_selections
 *  The pcr selections to use when building the pcr policy. It follows the PCR selection
 *  specifications in the man page for tpm2_listpcrs. If using a raw_pcrs_file, this spec
 *  must be the same as supplied to tpm2_listpcrs.
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_policy_build_pcr(ESYS_CONTEXT *context,
        tpm2_session *policy_session,
        const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections);


/**
 * Enables a signing authority to authorize policies
 * @param ectx
 *   The Enhanced system api context
 * @param policy_session
 *   The policy session that has the policy digest to be authorized
 * @param policy_digest_path
 *   The policy digest file that needs to be authorized by signing authority
 * @param policy_qualifier_path
 *   The policy qualifier data that concatenates with approved policies
 * @param verifying_pubkey_name_path
 *   The name of the public key that verifies the signature of the signer
 * @param ticket_path
 *   The verification ticket generated when TPM verifies the signature
 * @return
 *   tool_rc indicating status.
 */
tool_rc tpm2_policy_build_policyauthorize(
    ESYS_CONTEXT *ectx,
    tpm2_session *policy_session,
    const char *policy_digest_path,
    const char *policy_qualifier_path,
    const char *verifying_pubkey_name_path,
    const char *ticket_path);

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
    tpm2_session *policy_session, TPML_DIGEST policy_list);

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
    tpm2_session *policy_session, tpm2_session *secret_session,
    TPM2_HANDLE handle);

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
tool_rc tpm2_policy_get_digest(ESYS_CONTEXT *context,
        tpm2_session *session,
        TPM2B_DIGEST **policy_digest);

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
        tpm2_session *session);

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
    tpm2_session *session, uint32_t command_code);

/**
 * Policy to restrict tpm object authorization to specific locality
 *
 * @param ectx
 *   The Enhanced system api (ESAPI_) context.
 * @param policy_session
 *   The policy session into which the policy digest is extended into
 * @param locality
 *   The locality of the command authorized to use the object
 */
bool tpm2_policy_build_policylocality(ESYS_CONTEXT *ectx,
    tpm2_session *session, TPMA_LOCALITY locality);

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
 */
bool tpm2_policy_build_policyduplicationselect(ESYS_CONTEXT *ectx,
    tpm2_session *session,
    const char *obj_name_path,
    const char *new_parent_name_path,
    TPMI_YES_NO is_include_obj);

#endif /* TPM2_POLICY_H_ */
