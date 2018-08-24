//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
#ifndef TPM2_POLICY_H_
#define TPM2_POLICY_H_

#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "tpm2_session.h"

/**
 * Build a PCR policy via Esys_PolicyPCR.
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
 *  true on success, false otherwise.
 */
bool tpm2_policy_build_pcr(ESYS_CONTEXT *context,
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
 *   true on success, false otherwise.
 */
bool tpm2_policy_build_policyauthorize(
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
 *   true on success, false otherwise.
 */
bool tpm2_policy_build_policyor(ESYS_CONTEXT *ectx,
    tpm2_session *policy_session, TPML_DIGEST policy_list);

/**
 * Enables secret (password/hmac) based authorization to a policy.
 *
 * @param ectx
 *  The Enhanced system api (ESAPI) context
 * @param policy_session into which the policy digest is extended into
 *  The policy session
 * @param[in] session_data
 *  The command authentication data
 * @param[in] handle
 *  The handle-id of the authentication object
 *
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_policy_build_policysecret(ESYS_CONTEXT *ectx,
    tpm2_session *policy_session, TPMS_AUTH_COMMAND session_data,
    TPM2_HANDLE handle);

/**
 * Retrieves the policy digest for a session via Esys_PolicyGetDigest.
 * @param context
 *  The Enhanced System API (ESAPI) context.
 * @param session
 *  The session whose digest to query.
 * @param policy_digest
 *  The retrieved digest, only valid on true returns.
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_policy_get_digest(ESYS_CONTEXT *context,
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
 *  true on success, false otherwise.
 */
bool tpm2_policy_build_policypassword(ESYS_CONTEXT *ectx,
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
 */
bool tpm2_policy_build_policycommandcode(ESYS_CONTEXT *ectx,
    tpm2_session *session, uint32_t command_code);

#endif /* TPM2_POLICY_H_ */
