#ifndef LIB_TPM2_NV_UTIL_H_
#define LIB_TPM2_NV_UTIL_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

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
bool tpm2_nv_util_attrs_to_val(char *attribute_list, TPMA_NV *nvattrs);

#endif /* LIB_TPM2_NV_UTIL_H_ */
