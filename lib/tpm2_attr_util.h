/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_ATTR_UTIL_H_
#define LIB_TPM2_ATTR_UTIL_H_

#include <stdbool.h>

#include <tss2/tss2_sys.h>

/**
 * Converts a list of | (pipe) separated attributes as defined in tavle 204
 * of https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 * to an actual bit field representation. The trailing TPMA_NV_ can be omitted and must be lower-case.
 * For example, TPMA_NV_PPWRITE, becomes ppwrite. To append them together, just do the pipe in between.
 * ppwrite|ownerwrite.
 *
 * @param attribute_list
 *  The attribute string to parse, which may be modified in place.
 * @param nvattrs
 *  The TPMA_NV attributes set based on the attribute list. Only valid on true returns.
 * @return
 *  true on success, false on error.
 */
bool tpm2_attr_util_nv_strtoattr(char *attribute_list, TPMA_NV *nvattrs);

/**
 * Like tpm2_attr_util_nv_strtoattr() but converts TPMA_OBJECT attributes as defined in:
 * Table 31 of https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 * @param attribute_list
 *   The attribute string to parse, which may be modified in place.
 *  The TPMA_OBJECT attributes set based on the attribute list. Only valid on true returns.
 * @return
 *  true on success, false on error.
 */
bool tpm2_attr_util_obj_strtoattr(char *attribute_list, TPMA_OBJECT *objattrs);

/**
 * Converts a numerical or friendly string described object attribute into the
 * TPMA_OBJECT. Similar to tpm2_alg_util_from_optarg().
 * @param argvalue
 *  Either a raw numeric for a UINT32 or a friendly name object attribute list
 *  as in tpm2_attr_util_nv_strtoattr().
 * @param objattrs
 *  The converted bits for a TPMA_OBJECT
 * @return
 *  true on success or false on error.
 */
bool tpm2_attr_util_obj_from_optarg(char *argvalue, TPMA_OBJECT *objattrs);

/**
 * Converts a TPMA_NV structure to a friendly name style string.
 * @param nvattrs
 *  The nvattrs to convert to nice name.
 * @return A string allocated with calloc(), callers shall use
 * free() to free it. The string is a null terminated text representation
 * of the TPMA_NV attributes.
 */
char *tpm2_attr_util_nv_attrtostr(TPMA_NV nvattrs);

/**
 * Like tpm2_nv_util_obj_strtoattr() but converts TPMA_OBJECT attributes as defined in:
 * Table 31 of https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 * @param objattrs
 *  The object parameters to convert to a name
 * @return
 *  The name of the object attrs as a string that must be freed via free().
 */
char *tpm2_attr_util_obj_attrtostr(TPMA_OBJECT objattrs);

#endif /* LIB_TPM2_ATTR_UTIL_H_ */
