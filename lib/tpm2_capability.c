/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_capability.h"

#define APPEND_CAPABILITY_INFORMATION(capability, field, subfield, max_count) \
    if (fetched_data->data.capability.count > max_count - property_count) { \
        fetched_data->data.capability.count = max_count - property_count; \
    } \
\
    memmove(&(*capability_data)->data.capability.field[property_count], \
            fetched_data->data.capability.field, \
            fetched_data->data.capability.count * sizeof(fetched_data->data.capability.field[0])); \
    property_count += fetched_data->data.capability.count; \
\
    (*capability_data)->data.capability.count = property_count; \
\
    if (more_data && property_count < count && fetched_data->data.capability.count) { \
        property = (*capability_data)->data.capability.field[property_count - 1]subfield + 1; \
    } else { \
        more_data = false; \
    }

tool_rc tpm2_capability_get_ex(ESYS_CONTEXT *ectx, TPM2_CAP capability,
        UINT32 property, UINT32 count, bool ignore_more_data,
        TPMS_CAPABILITY_DATA **capability_data) {

    TPMI_YES_NO more_data = 0;
    UINT32 property_count = 0;
    *capability_data = NULL;

    do {

        /* fetch capability info */
        TPMS_CAPABILITY_DATA *fetched_data = NULL;
        tool_rc rc = tpm2_get_capability(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, capability, property, count - property_count,
                &more_data, &fetched_data);
        LOG_INFO("GetCapability: capability: 0x%x, property: 0x%x", capability,
                property);

        if (rc != tool_rc_success) {
            if (*capability_data) {
                free(*capability_data);
                *capability_data = NULL;
            }
            return rc;
        }

        if (fetched_data->capability != capability) {
            LOG_ERR("TPM returned different capability than requested: 0x%x != "
                    "0x%x", fetched_data->capability, capability);
            free(fetched_data);
            if (*capability_data) {
                free(*capability_data);
                *capability_data = NULL;
            }
            return tool_rc_general_error;
        }

        if (*capability_data == NULL) {
            /* reuse the TPM's result structure */
            *capability_data = fetched_data;

            if (!more_data || ignore_more_data) {
                /* there won't be another iteration of the loop, just return the result unmodified */
                return tool_rc_success;
            }
        }

        /* append the TPM's results to the initial structure, as long as there is still space left */
        switch (capability) {
        case TPM2_CAP_ALGS:
            APPEND_CAPABILITY_INFORMATION(algorithms, algProperties, .alg,
                    TPM2_MAX_CAP_ALGS);
            break;
        case TPM2_CAP_HANDLES:
            APPEND_CAPABILITY_INFORMATION(handles, handle,,
                    TPM2_MAX_CAP_HANDLES);
            break;
        case TPM2_CAP_COMMANDS:
            APPEND_CAPABILITY_INFORMATION(command, commandAttributes,,
                    TPM2_MAX_CAP_CC);
            /* workaround because tpm2-tss does not implement attribute commandIndex for TPMA_CC */
            property &= TPMA_CC_COMMANDINDEX_MASK;
            break;
        case TPM2_CAP_PP_COMMANDS:
            APPEND_CAPABILITY_INFORMATION(ppCommands, commandCodes,,
                    TPM2_MAX_CAP_CC);
            break;
        case TPM2_CAP_AUDIT_COMMANDS:
            APPEND_CAPABILITY_INFORMATION(auditCommands, commandCodes,,
                    TPM2_MAX_CAP_CC);
            break;
        case TPM2_CAP_PCRS:
            APPEND_CAPABILITY_INFORMATION(assignedPCR, pcrSelections, .hash,
                    TPM2_NUM_PCR_BANKS);
            break;
        case TPM2_CAP_TPM_PROPERTIES:
            APPEND_CAPABILITY_INFORMATION(tpmProperties, tpmProperty, .property,
                    TPM2_MAX_TPM_PROPERTIES);
            break;
        case TPM2_CAP_PCR_PROPERTIES:
            APPEND_CAPABILITY_INFORMATION(pcrProperties, pcrProperty, .tag,
                    TPM2_MAX_PCR_PROPERTIES);
            break;
        case TPM2_CAP_ECC_CURVES:
            APPEND_CAPABILITY_INFORMATION(eccCurves, eccCurves,,
                    TPM2_MAX_ECC_CURVES);
            break;
        default:
            LOG_ERR("Unsupported capability with moreData True,"
                    "try with option -i, got: 0x%x\n", capability);
            if (fetched_data != *capability_data) {
                free(fetched_data);
            }
            free(*capability_data);
            *capability_data = NULL;
            return tool_rc_general_error;
        }

        if (fetched_data != *capability_data) {
            free(fetched_data);
        }
    } while (more_data);

    return tool_rc_success;
}

tool_rc tpm2_capability_get(ESYS_CONTEXT *ectx, TPM2_CAP capability,
        UINT32 property, UINT32 count,
        TPMS_CAPABILITY_DATA **capability_data) {

    return tpm2_capability_get_ex(ectx, capability,
            property, count, false, capability_data);
}

tool_rc tpm2_capability_find_vacant_persistent_handle(ESYS_CONTEXT *ctx,
        bool is_platform, TPMI_DH_PERSISTENT *vacant) {

    TPMS_CAPABILITY_DATA *capability_data;
    bool handle_found = false;
    tool_rc rc = tpm2_capability_get(ctx, TPM2_CAP_HANDLES,
            TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &capability_data);
    if (rc != tool_rc_success) {
        return rc;
    }

    UINT32 count = capability_data->data.handles.count;
    if (count == 0) {
        /* There aren't any persistent handles, so use the first */
        *vacant = is_platform ? TPM2_PLATFORM_PERSISTENT : TPM2_PERSISTENT_FIRST;
        handle_found = true;
    } else if (count == TPM2_MAX_CAP_HANDLES) {
        /* All persistent handles are already in use */
        goto out;
    } else if (count < TPM2_MAX_CAP_HANDLES) {
        /*
         * iterate over used handles to ensure we're selecting
         * the next available handle.
         *
         * Platform handles start at a higher hange
         */
        UINT32 i;
        for (i = is_platform ? TPM2_PLATFORM_PERSISTENT : TPM2_PERSISTENT_FIRST;
                i <= (UINT32) TPM2_PERSISTENT_LAST; ++i) {
            bool inuse = false;
            UINT32 c;
            for (c = 0; c < count; ++c) {
                if (capability_data->data.handles.handle[c] == i) {
                    inuse = true;
                    break;
                }
            }

            if (!is_platform && i >= TPM2_PLATFORM_PERSISTENT) {
                break;
            }

            if (!inuse) {
                *vacant = i;
                handle_found = true;
                break;
            }
        }
    }

out:
    free(capability_data);
    return handle_found ? tool_rc_success : tool_rc_general_error;
}
