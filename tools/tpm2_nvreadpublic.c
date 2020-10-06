/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

typedef struct tpm2_nvreadpublic_ctx tpm2_nvreadpublic_ctx;
struct tpm2_nvreadpublic_ctx {
    TPMI_RH_NV_INDEX nv_index;
};

static tpm2_nvreadpublic_ctx ctx;

static tool_rc print_nv_public(ESYS_CONTEXT *context, TPMI_RH_NV_INDEX index, TPM2B_NV_PUBLIC *nv_public) {

    ESYS_TR tr_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_tr_from_tpm_public(context, index,
            &tr_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    tpm2_tool_output("0x%x:\n", index);


    char *attrs = tpm2_attr_util_nv_attrtostr(nv_public->nvPublic.attributes);
    if (!attrs) {
        LOG_ERR("Could not convert attributes to string form");
    }

    const char *alg = tpm2_alg_util_algtostr(nv_public->nvPublic.nameAlg,
            tpm2_alg_util_flags_hash);
    if (!alg) {
        LOG_ERR("Could not convert algorithm to string form");
    }

    TPM2B_NAME *name = NULL;
    rc = tpm2_tr_get_name(context, tr_handle,
            &name);
    if (rc != tool_rc_success) {
        free(attrs);
        return rc;
    }

    tpm2_tool_output("  name: ");
    UINT16 i;
    for (i = 0; i < name->size; i++) {
        tpm2_tool_output("%02x", name->name[i]);
    }
    tpm2_tool_output("\n");

    Esys_Free(name);

    tpm2_tool_output("  hash algorithm:\n");
    tpm2_tool_output("    friendly: %s\n", alg);
    tpm2_tool_output("    value: 0x%X\n", nv_public->nvPublic.nameAlg);

    tpm2_tool_output("  attributes:\n");
    tpm2_tool_output("    friendly: %s\n", attrs);
    tpm2_tool_output("    value: 0x%X\n",
            tpm2_util_ntoh_32(nv_public->nvPublic.attributes));

    tpm2_tool_output("  size: %d\n", nv_public->nvPublic.dataSize);

    if (nv_public->nvPublic.authPolicy.size) {
        tpm2_tool_output("  authorization policy: ");

        UINT16 i;
        for (i = 0; i < nv_public->nvPublic.authPolicy.size; i++) {
            tpm2_tool_output("%02X", nv_public->nvPublic.authPolicy.buffer[i]);
        }
        tpm2_tool_output("\n");
    }

    free(attrs);

    return tool_rc_success;
}

static tool_rc nv_readpublic(ESYS_CONTEXT *context) {


    TPMS_CAPABILITY_DATA *capability_data = NULL;
    if (ctx.nv_index == 0) {
        tool_rc rc = tpm2_getcap(context, TPM2_CAP_HANDLES, TPM2_HT_NV_INDEX << 24,
                TPM2_PT_NV_INDEX_MAX, NULL, &capability_data);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else {
        capability_data = calloc(1, sizeof(*capability_data));
        if (!capability_data) {
            LOG_ERR("oom");
            return tool_rc_general_error;
        }
        capability_data->data.handles.count = 1;
        capability_data->data.handles.handle[0] = ctx.nv_index;
    }
    UINT32 i;
    for (i = 0; i < capability_data->data.handles.count; i++) {
        TPMI_RH_NV_INDEX index = capability_data->data.handles.handle[i];

        TPM2B_NV_PUBLIC *nv_public;
        tool_rc rc = tpm2_util_nv_read_public(context, index, &nv_public);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to read the public part of NV index 0x%X", index);
            free(capability_data);
            return rc;
        }

        rc = print_nv_public(context, index, nv_public);
        free(nv_public);
        tpm2_tool_output("\n");
        if (rc != tool_rc_success) {
            free(capability_data);
            return rc;
        }
    }

    free(capability_data);
    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL,
            on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    return nv_readpublic(context);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvreadpublic", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
