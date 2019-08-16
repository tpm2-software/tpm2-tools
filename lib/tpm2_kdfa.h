/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_TPM_KDFA_H_
#define SRC_TPM_KDFA_H_

#include <tss2/tss2_sys.h>

/* TODO DOCUMENT ME */
/**
 *
 * @param hashAlg
 * @param key
 * @param label
 * @param contextU
 * @param contextV
 * @param bits
 * @param resultKey
 * @return
 */
TSS2_RC tpm2_kdfa(TPMI_ALG_HASH hash_alg, TPM2B *key, char *label,
        TPM2B *context_u, TPM2B *context_v, UINT16 bits,
        TPM2B_MAX_BUFFER *result_key);

#endif /* SRC_TPM_KDFA_H_ */
