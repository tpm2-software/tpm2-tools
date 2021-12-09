/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>

#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm2_nvreadpublic_ctx tpm2_nvreadpublic_ctx;
struct tpm2_nvreadpublic_ctx {
    /*
     * Inputs
     */
    TPMI_RH_NV_INDEX nv_index;
    TPMS_CAPABILITY_DATA *capability_data;

    /*
     * Outputs
     */
    TPM2B_NV_PUBLIC **nv_public_list;
  
    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm2_nvreadpublic_ctx ctx = {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc nv_readpublic(ESYS_CONTEXT *ectx) {

    tool_rc rc = tool_rc_success;
    uint32_t i;
    for (i = 0; i < ctx.capability_data->data.handles.count; i++) {
        rc = tpm2_util_nv_read_public(ectx,
            ctx.capability_data->data.handles.handle[i], &ctx.nv_public_list[i],
            &ctx.cp_hash, &ctx.rp_hash, ctx.parameter_hash_algorithm);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to read the public part of NV index 0x%X",
                ctx.capability_data->data.handles.handle[i]);
            break;
        }
    }

    return rc;
}

static tool_rc print_nv_public(ESYS_CONTEXT *context, TPMI_RH_NV_INDEX index,
    TPM2B_NV_PUBLIC *nv_public) {

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

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    uint32_t i;
    for (i = 0; i < ctx.capability_data->data.handles.count; i++) {
        if (ctx.is_command_dispatch) {
            rc = print_nv_public(ectx,
                ctx.capability_data->data.handles.handle[i],
                ctx.nv_public_list[i]);
            tpm2_tool_output("\n");
            if (rc != tool_rc_success) {
                return rc;
            }
        }
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
        rc = is_file_op_success ? tool_rc_success : tool_rc_general_error;
    }

    return rc;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations dependent on loaded objects
     */
    tool_rc rc = tool_rc_success;
    if (ctx.nv_index == 0 && ctx.is_command_dispatch) {
        rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES,
            TPM2_HT_NV_INDEX << 24, TPM2_PT_NV_INDEX_MAX, NULL,
            &ctx.capability_data);
        if (rc != tool_rc_success) {
            return rc;
        }
    }
    
    if (ctx.nv_index != 0 || !ctx.is_command_dispatch) {
        /*
         * This path is taken for calculating cpHash as NV index cannot be 0
         * with cpHash option specified
         */
        ctx.capability_data = calloc(1, sizeof(*ctx.capability_data));
        if (!ctx.capability_data) {
            LOG_ERR("oom");
            return tool_rc_general_error;
        }
        ctx.capability_data->data.handles.count = 1;
        ctx.capability_data->data.handles.handle[0] = ctx.nv_index;
    }

    /*
     * Allocate space for holding NV public data for all indices.
     * Individual index NV public structure is allocated by Esys_NV_ReadPublic.
     */
    ctx.nv_public_list =
    malloc(ctx.capability_data->data.handles.count * sizeof(TPM2B_NV_PUBLIC*));
    /*
     * When calculating cpHash only, Esys_NV_Readpublic isn't invoked and so
     * allocate space for one index.
     */
    if (!ctx.is_command_dispatch) {
        ctx.nv_public_list[0] = malloc(sizeof(TPM2B_NV_PUBLIC));
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        0,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    return rc;
}

static tool_rc check_options(ESYS_CONTEXT *ectx) {

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    /*
     * Prevent overwriting pHash by allowing only one index at a time.
     */
    if ((ctx.cp_hash_path || ctx.rp_hash_path) && ctx.nv_index == 0) {
        LOG_ERR("Must specify NV Index to calculate cpHash");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_arg(int argc, char **argv) {

    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool on_option(char key, char *value) {

    bool result = true;
    switch (key) {
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.rp_hash_path = value;
        break;
    }

    return result;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "cphash", required_argument, NULL,  0  },
        { "rphash", required_argument, NULL,  1  },
    };

    *opts = tpm2_options_new(0, ARRAY_LEN(topts), topts, on_option, on_arg, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = nv_readpublic(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_output(ectx);

}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */
    uint32_t i = 0;
    if (ctx.capability_data) {
        for (i = 0; i < ctx.capability_data->data.handles.count; i++) {
            free(ctx.nv_public_list[i]);
        }
        free(ctx.capability_data);
    }

    free(ctx.nv_public_list);

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvreadpublic", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
