//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "tpm2_util.h"

#include "tpm2_capability.h"

static size_t tpm2_get_property_data_size(TPM2_CAP capability, size_t *maxSize) {

    size_t size;
    TPMS_CAPABILITY_DATA dummy;

    switch (capability) {
        case TPM2_CAP_ALGS:
            size = sizeof(dummy.data.algorithms.algProperties[0]);
            *maxSize = TPM2_MAX_CAP_ALGS;
            break;
        case TPM2_CAP_HANDLES:
            size = sizeof(dummy.data.handles.handle[0]);
            *maxSize = TPM2_MAX_CAP_HANDLES;
            break;
        case TPM2_CAP_COMMANDS:
            size = sizeof(dummy.data.command.commandAttributes[0]);
            *maxSize = TPM2_MAX_CAP_CC;
            break;
        case TPM2_CAP_PP_COMMANDS:
            size = sizeof(dummy.data.ppCommands.commandCodes[0]);
            *maxSize = TPM2_MAX_CAP_CC;
            break;
        case TPM2_CAP_AUDIT_COMMANDS:
            size = sizeof(dummy.data.auditCommands.commandCodes[0]);
            *maxSize = TPM2_MAX_CAP_CC;
            break;
        case TPM2_CAP_PCRS:
            size = sizeof(dummy.data.assignedPCR.pcrSelections[0]);
            *maxSize = TPM2_NUM_PCR_BANKS;
            break;
        case TPM2_CAP_TPM_PROPERTIES:
            size = sizeof(dummy.data.tpmProperties.tpmProperty[0]);
            *maxSize = TPM2_MAX_TPM_PROPERTIES;
            break;
        case TPM2_CAP_PCR_PROPERTIES:
            size = sizeof(dummy.data.pcrProperties.pcrProperty[0]);
            *maxSize = TPM2_MAX_PCR_PROPERTIES;
            break;
        case TPM2_CAP_ECC_CURVES:
            size = sizeof(dummy.data.eccCurves.eccCurves[0]);
            *maxSize = TPM2_MAX_ECC_CURVES;
            break;
        case TPM2_CAP_VENDOR_PROPERTY:
            size = sizeof(dummy.data.intelPttProperty.property[0]);
            *maxSize = TPM2_MAX_PTT_PROPERTIES;
            break;
        default:
            size = 0;
            LOG_ERR("Unable to determine property size for capability:  %d\n",
                capability);
            break;
    }

    return size;
}

static size_t tpm2_get_property(TPM2_CAP capability, TPMS_CAPABILITY_DATA *cap,
    UINT32 i) {

    size_t size;

    switch (capability) {
        case TPM2_CAP_ALGS:
            return cap->data.algorithms.algProperties[i].alg;
            break;
        case TPM2_CAP_HANDLES:
            return cap->data.handles.handle[i];
            break;
        case TPM2_CAP_COMMANDS:
            return cap->data.command.commandAttributes[i];
            break;
        case TPM2_CAP_PP_COMMANDS:
            return cap->data.ppCommands.commandCodes[i];
            break;
        case TPM2_CAP_AUDIT_COMMANDS:
            return cap->data.ppCommands.commandCodes[i];
            break;
        case TPM2_CAP_PCRS:
            return cap->data.assignedPCR.pcrSelections[i].hash;
            break;
        case TPM2_CAP_TPM_PROPERTIES:
            return cap->data.tpmProperties.tpmProperty[i].property;
            break;
        case TPM2_CAP_PCR_PROPERTIES:
            return cap->data.pcrProperties.pcrProperty[i].tag;
            break;
        case TPM2_CAP_ECC_CURVES:
            return cap->data.eccCurves.eccCurves[i];
            break;
        case TPM2_CAP_VENDOR_PROPERTY:
            return cap->data.intelPttProperty.property[i];
            break;
        default:
            size = 0;
            LOG_ERR("Unable to determine property size for capability:  %d\n",
                capability);
            break;
    }

    return size;
}

bool tpm2_capability_get (ESYS_CONTEXT *ectx,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 count,
        TPMS_CAPABILITY_DATA **capability_data) {

    TPMI_YES_NO more_data;
    *capability_data = NULL;
    size_t maxSize;

    size_t property_size = tpm2_get_property_data_size(capability, &maxSize);

    if (!property_size) {
        return false;
    }

    *capability_data = calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    UINT32 property_idx = 0;
    UINT32 j = 0;

    do {

        /* fetch capability info */
        TPMS_CAPABILITY_DATA *fetched_data = NULL;
        TSS2_RC rval = Esys_GetCapability (ectx,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            capability, property, count,
                            &more_data, &fetched_data);
        LOG_INFO("GetCapability: capability: 0x%x, property: 0x%x", capability,
            property);

        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed to GetCapability: capability: 0x%x, property: 0x%x",
                     capability, property);
            LOG_PERR(ESys_GetCapability, rval);
            return false;
        }

        UINT32 i;
        UINT32 existing = 0;
        /* Copy all existing results into the newly allocated area */
        existing = fetched_data->data.algorithms.count;
        for (i = j; i < existing; i++) {
            if(property_idx>maxSize){
                LOG_ERR("Too much properties requested.");
            }
            (*capability_data)->data.algorithms.algProperties[property_idx] = fetched_data->data.algorithms.algProperties[i];
            property_idx += 1;
        }
        j=1;
        if(property_idx > 0){
            property = tpm2_get_property(capability, *capability_data,
                property_idx-1);
            (*capability_data)->data.algorithms.count = property_idx;
        }

        free(fetched_data);
    } while (more_data);

    return true;
}

bool tpm2_capability_find_vacant_persistent_handle (ESYS_CONTEXT *ctx,
        UINT32 *vacant) {

    TPMS_CAPABILITY_DATA *capability_data;
    bool handle_found = false;
    bool ret = tpm2_capability_get(ctx, TPM2_CAP_HANDLES,
                    TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES,
                    &capability_data);
    if (!ret) {
        goto out;
    }

    UINT32 count = capability_data->data.handles.count;
    if (count == 0) {
        /* There aren't any persistent handles, so use the first */
        *vacant = TPM2_PERSISTENT_FIRST;
        handle_found = true;
    } else if (count == TPM2_MAX_CAP_HANDLES) {
        /* All persistent handles are already in use */
        goto out;
    } else if (count < TPM2_MAX_CAP_HANDLES) {
        /* iterate over used handles to ensure we're selecting
            the next available handle. */
        UINT32 i;
        for (i = TPM2_PERSISTENT_FIRST;
            i <= (UINT32)TPM2_PERSISTENT_LAST;
            ++i) {
            bool inuse = false;
            UINT32 c;
            for (c = 0; c < count; ++c) {
                if (capability_data->data.handles.handle[c] == i) {
                    inuse = true;
                    break;
                }
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
    return handle_found;
}

