#ifndef SRC_TPM_HASH_H_
#define SRC_TPM_HASH_H_

#include <sapi/tpm20.h>

/**
 * Hashes a list of TPM2B_DIGEST buffers via the tpm.
 * @param sapi_context
 *  The system api context.
 * @param hash_alg
 *  The hashing algorithm to use.
 * @param hierarchy
 *  The hierarchy.
 * @param num_buffers
 *  The number of buffers to hash in the list.
 * @param buffer_list
 *  The buffer list.
 * @param result
 *  The digest result.
 * @param validation
 *  The validation ticket. Note that some hierarchies don't produce a
 *  validation ticket and thus size will be 0.
 * @return
 *  TPM_RC_SUCCESS on success, or other TPM_RCs on error.
 */
TPM_RC tpm_hash_sequence(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hash_alg,
        TPMI_RH_HIERARCHY hierarchy, size_t num_buffers, TPM2B_DIGEST *buffer_list,
        TPM2B_DIGEST *result, TPMT_TK_HASHCHECK *validation);

/**
 * Hashes a BYTE array via the tpm.
 * @param sapi_context
 *  The system api context.
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
 *  TPM_RC_SUCCESS on success, or other TPM_RCs on error.
 */
TPM_RC tpm_hash_compute_data(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, BYTE *buffer, UINT16 length,
        TPM2B_DIGEST *result, TPMT_TK_HASHCHECK *validation);

/**
 * Hashes a FILE * object via the tpm.
 * @param sapi_context
 *  The system api context.
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
 *  TPM_RC_SUCCESS on success, or other TPM_RCs on error.
 */
TPM_RC tpm_hash_file(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH halg,
        TPMI_RH_HIERARCHY hierarchy, FILE *input, TPM2B_DIGEST *result,
        TPMT_TK_HASHCHECK *validation);

#endif /* SRC_TPM_HASH_H_ */
