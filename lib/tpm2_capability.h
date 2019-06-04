/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_CAPABILITY_H_
#define LIB_TPM2_CAPABILITY_H_

#include <tss2/tss2_esys.h>

/**
 * Invokes GetCapability to retrieve the current value of a capability from the
 * TPM.
 * @param context
 *  Enhanced system api (ESAPI) context
 * @param capability
 *  the capability being requested from the TPM
 * @param property
 *  property
 * @param count
 *  maximum number of values to return
 * @param capability_data
 *  capability data structure to populate
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_capability_get (ESYS_CONTEXT *context,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 count,
        TPMS_CAPABILITY_DATA **capability_data);

/**
 * Attempts to find a vacant handle in the persistent handle namespace.
 * @param ctx
 *  Enhanced System API (ESAPI) context
 * @param vacant
 *  the vacant handle found by the function if True returned
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_capability_find_vacant_persistent_handle (ESYS_CONTEXT *ctx,
        UINT32 *vacant);

#endif /* LIB_TPM2_CAPABILITY_H_ */
