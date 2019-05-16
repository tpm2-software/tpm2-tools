/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <tss2/tss2_esys.h>

#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_util.h"
#include "log.h"
#include "tpm2_tool.h"

static void print_nv_public(TPM2B_NV_PUBLIC *nv_public) {

    char *attrs = tpm2_attr_util_nv_attrtostr(nv_public->nvPublic.attributes);
    if (!attrs) {
        LOG_ERR("Could not convert attributes to string form");
    }

    const char *alg = tpm2_alg_util_algtostr(nv_public->nvPublic.nameAlg, tpm2_alg_util_flags_hash);
    if (!alg) {
        LOG_ERR("Could not convert algorithm to string form");
    }

    tpm2_tool_output("  hash algorithm:\n");
    tpm2_tool_output("    friendly: %s\n", alg);
    tpm2_tool_output("    value: 0x%X\n",
            nv_public->nvPublic.nameAlg);

    tpm2_tool_output("  attributes:\n");
    tpm2_tool_output("    friendly: %s\n", attrs);
    tpm2_tool_output("    value: 0x%X\n",
            tpm2_util_ntoh_32(nv_public->nvPublic.attributes));

    tpm2_tool_output("  size: %d\n",
               nv_public->nvPublic.dataSize);

    if (nv_public->nvPublic.authPolicy.size) {
        tpm2_tool_output("  authorization policy: ");

        UINT16 i;
        for (i=0; i<nv_public->nvPublic.authPolicy.size; i++) {
            tpm2_tool_output("%02X", nv_public->nvPublic.authPolicy.buffer[i] );
        }
        tpm2_tool_output("\n");
    }

    free(attrs);
}

static bool nv_list(ESYS_CONTEXT *context) {

    TPMS_CAPABILITY_DATA *capabilityData;
    UINT32 property = tpm2_util_hton_32(TPM2_HT_NV_INDEX);
    TSS2_RC rval = Esys_GetCapability(context,
                                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                      TPM2_CAP_HANDLES, property,
                                      TPM2_PT_NV_INDEX_MAX,
                                      NULL, &capabilityData);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetCapability, rval);
        return false;
    }

    UINT32 i;
    for (i = 0; i < capabilityData->data.handles.count; i++) {
        TPMI_RH_NV_INDEX index = capabilityData->data.handles.handle[i];

        tpm2_tool_output("0x%x:\n", index);

        TPM2B_NV_PUBLIC *nv_public;
        bool res = tpm2_util_nv_read_public(context, index, &nv_public);
        if (!res) {
            LOG_ERR("Failed to read the public part of NV index 0x%X", index);
            free(capabilityData);
            return false;
        }
        print_nv_public(nv_public);
        free(nv_public);
        tpm2_tool_output("\n");
    }

    free(capabilityData);
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, NULL,
            0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    return !nv_list(context);
}
