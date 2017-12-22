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

#include <sapi/tpm20.h>

#include "tpm2_session.h"

/**
 * Build a PCR policy via Tss2_Sys_PolicyPCR.
 * @param sapi_context
 *  The system api context.
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
bool tpm2_policy_build_pcr(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session *policy_session,
        const char *raw_pcrs_file,
        TPML_PCR_SELECTION *pcr_selections);

/**
 * Retrieves the policy digest for a session via Tss2_Sys_PolicyGetDigest.
 * @param sapi_context
 *  The system api context.
 * @param session
 *  The session whose digest to query.
 * @param policy_digest
 *  The retrieved digest, only valid on true returns.
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_policy_get_digest(TSS2_SYS_CONTEXT *sapi_context,
        tpm2_session *session,
        TPM2B_DIGEST *policy_digest);

#endif /* TPM2_POLICY_H_ */
