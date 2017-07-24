#ifndef SRC_POLICY_H_
#define SRC_POLICY_H_

#include <sapi/tpm20.h>
#include <stdbool.h>

#include "tpm2_util.h"
#include "tpm_hash.h"
#include "tpm_session.h"

TPM_RC tpm2_policy_pcr_build(TSS2_SYS_CONTEXT *sapi_context,
                             SESSION *policy_session,
                             TPML_PCR_SELECTION pcr_selections,
                             char *raw_pcrs_file);
TPM_RC tpm2_policy_build(TSS2_SYS_CONTEXT *sapi_context,
                         SESSION **policy_session,
                         TPM_SE policy_session_type,
                         TPMI_ALG_HASH policy_digest_hash_alg,
                         TPML_PCR_SELECTION pcr_selections,
                         char *raw_pcrs_file,
                         TPM2B_DIGEST *policy_digest,
                         bool extend_policy_session,
        TPM_RC (*build_policy_function)(TSS2_SYS_CONTEXT *sapi_context,
                                        SESSION *policy_session,
                                        TPML_PCR_SELECTION pcr_selections,
                                        char *raw_pcrs_file));

#endif /* SRC_POLICY_H_ */
