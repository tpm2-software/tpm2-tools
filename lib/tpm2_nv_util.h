#ifndef LIB_TPM2_NV_UTIL_H_
#define LIB_TPM2_NV_UTIL_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

#include "tpm2_util.h"

/**
 * Converts a list of | (pipe) separated attributes as defined in tavle 204
 * of https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 * to an actual bit field representation. The trailing TPMA_NV_ can be omitted and must be lower-case.
 * For exmaple, TPMA_NV_PPWRITE, bcomes ppwrite. To append them together, just do the pipe inbetwwen.
 * ppwrite|ownerwrite.
 *
 * @param attribute_list
 *  The attribute string to parse, which may be modified in place.
 * @param nvattrs
 *  The TPMA_NV attributes set based on the attribute list. Only valid on true returns.
 * @return
 *  true on success, false on error.
 */
bool tpm2_nv_util_strtoattr(char *attribute_list, TPMA_NV *nvattrs);

/**
 * Converts a TPMA_NV structure to a friendly name style string.
 * @param nvattrs
 *  The nvattrs to convert to nice name.
 * @return A string allocated with calloc(), callers shall use
 * free() to free it. The string is a null terminated text representation
 * of the TPMA_NV attributes.
 */
char *tpm2_nv_util_attrtostr(TPMA_NV nvattrs);
/**
 * Reads the public portion of a Non-Volatile (nv) index.
 * @param sapi_context
 *  The system API context.
 * @param nv_index
 *  The index to read.
 * @param nv_public
 *  The public data structure to store the results in.
 * @return
 *  The error code from the TPM. TPM_RC_SUCCESS on success.
 * @note
 *  This is inlined to avoid a lib-dependency on TSS, and thus trying
 *  link the tools static utility library to the dynamic TSS library.
 */
static inline TPM_RC tpm2_util_nv_read_public(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_RH_NV_INDEX nv_index, TPM2B_NV_PUBLIC *nv_public) {

    TPM2B_NAME nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    return Tss2_Sys_NV_ReadPublic(sapi_context, nv_index, 0, nv_public,
            &nv_name, 0);
}

#endif /* LIB_TPM2_NV_UTIL_H_ */
