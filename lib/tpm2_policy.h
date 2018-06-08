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
#ifndef SRC_POLICY_H_
#define SRC_POLICY_H_

#include <tss2/tss2_sys.h>
#include <stdbool.h>

#include "tpm2_util.h"
#include "tpm_hash.h"
#include "tpm_session.h"

TSS2_RC tpm2_policy_pcr_build(TSS2_SYS_CONTEXT *sapi_context,
                             SESSION *policy_session,
                             TPML_PCR_SELECTION *pcr_selections,
                             char *raw_pcrs_file);
TSS2_RC tpm2_policy_build(TSS2_SYS_CONTEXT *sapi_context,
                         SESSION **policy_session,
                         TPM2_SE policy_session_type,
                         TPMI_ALG_HASH policy_digest_hash_alg,
                         TPML_PCR_SELECTION *pcr_selections,
                         char *raw_pcrs_file,
                         TPM2B_DIGEST *policy_digest,
                         bool extend_policy_session,
        TSS2_RC (*build_policy_function)(TSS2_SYS_CONTEXT *sapi_context,
                                        SESSION *policy_session,
                                        TPML_PCR_SELECTION *pcr_selections,
                                        char *raw_pcrs_file));

#endif /* SRC_POLICY_H_ */
