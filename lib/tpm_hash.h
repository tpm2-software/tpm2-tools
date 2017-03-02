#ifndef SRC_TPM_HASH_H_
#define SRC_TPM_HASH_H_

#include <sapi/tpm20.h>

UINT32 tpm_hash(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hashAlg,
	UINT16 size, BYTE *data, TPM2B_DIGEST *result);

int tpm_hash_compute_data(TSS2_SYS_CONTEXT *sapi_context, BYTE *buffer,
	UINT16 length, TPMI_ALG_HASH halg, TPM2B_DIGEST *result);

UINT32 tpm_hash_sequence(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hash_alg,
	size_t num_buffers, TPM2B_DIGEST *buffer_list, TPM2B_DIGEST *result);

#endif /* SRC_TPM_HASH_H_ */
