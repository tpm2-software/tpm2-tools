/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_TPM_HASH_H_
#define SRC_TPM_HASH_H_

#include <stdbool.h>

#include <tss2/tss2_esys.h>

/**
 * Hashes a BYTE array via the tpm.
 * @param context
 *  The esapi context.
 * @param hash_alg
 *  The hashing algorithm to use.
 * @param hierarchy
 *  The hierarchy.
 * @param buffer
 *  The data to hash.
 * @param length
 *  The length of the data.
 * @param result
 *  The digest result.
 * @param validation
 *  The validation ticket. Note that some hierarchies don't produce a
 *  validation ticket and thus size will be 0.
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_hash_compute_data(ESYS_CONTEXT *context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST **result, TPMT_TK_HASHCHECK **validation);

/**
 * Hashes a FILE * object via the tpm.
 * @param context
 *  The esapi context.
 * @param hash_alg
 *  The hashing algorithm to use.
 * @param hierarchy
 *  The hierarchy.
 * @param input
 *  The FILE object to hash.
 * @param result
 *  The digest result.
 * @param validation
 *  The validation ticket. Note that some hierarchies don't produce a
 *  validation ticket and thus size will be 0.
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_hash_file(ESYS_CONTEXT *ectx, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation);

#endif /* SRC_TPM_HASH_H_ */
