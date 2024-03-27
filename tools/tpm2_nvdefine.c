/* SPDX-License-Identifier: BSD-3-Clause */
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct tpm_nvdefine_ctx tpm_nvdefine_ctx;
#define MAX_SESSIONS 3
#define MAX_AUX_SESSIONS 2
struct tpm_nvdefine_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    TPMI_RH_NV_INDEX nv_index;
    bool size_set;
    UINT16 size;
    TPMA_NV nv_attribute;
    TPM2B_AUTH nv_auth;

    TPMI_ALG_HASH halg;
    char *policy_file;
    char *index_auth_str;

    TPM2B_NV_PUBLIC public_info;

    /*
     * Outputs
     */

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    bool is_command_dispatch;
    bool is_tcti_none;
    TPMI_ALG_HASH parameter_hash_algorithm;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

static tpm_nvdefine_ctx ctx = {
    .auth_hierarchy = {
        .ctx_path = "o",
    },
    .nv_auth = TPM2B_EMPTY_INIT,
    .halg = TPM2_ALG_SHA256,
    .public_info = TPM2B_EMPTY_INIT,
    .aux_session_handle[0] = ESYS_TR_NONE,
    .aux_session_handle[1] = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc nv_space_define(ESYS_CONTEXT *ectx) {

    tool_rc rc = tpm2_nv_definespace(ectx, &ctx.auth_hierarchy.object,
        &ctx.nv_auth, &ctx.public_info, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0],
        ctx.aux_session_handle[1]);
    if (rc != tool_rc_success) {
        if (ctx.is_command_dispatch) {
            LOG_ERR("Failed to create NV index 0x%x.", ctx.nv_index);
        }
        return rc;
    }

    if (ctx.is_command_dispatch) {
        tpm2_tool_output("nv-index: 0x%x\n", ctx.nv_index);
    }

    return rc;
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

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}


static void handle_default_attributes(void) {

    /* attributes set no need for defaults */
    if (ctx.nv_attribute) {
        return;
    }

    ESYS_TR h = ctx.auth_hierarchy.object.tr_handle;

    if (h == ESYS_TR_RH_OWNER) {
        ctx.nv_attribute |= TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;
    } else if (h == ESYS_TR_RH_PLATFORM) {
        ctx.nv_attribute |= TPMA_NV_PPWRITE | TPMA_NV_PPREAD | TPMA_NV_PLATFORMCREATE;
    } /* else it's an nv index for auth */

    /* if it has a policy file, set policy read and write vs auth read and write */
    if (ctx.policy_file) {
        ctx.nv_attribute |= TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD;
    } else {
        ctx.nv_attribute |= TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD;
    }
}

static tool_rc handle_no_index_specified(ESYS_CONTEXT *ectx, TPM2_NV_INDEX *chosen) {

    if (ctx.is_tcti_none) {
        *chosen = TPM2_HR_NV_INDEX;
        return tool_rc_success;
    }

    /* get the max NV index for the TPM */
    TPMS_CAPABILITY_DATA *capabilities = NULL;
    tool_rc rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED,
            TPM2_MAX_TPM_PROPERTIES, NULL, &capabilities);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPMS_TAGGED_PROPERTY *properties = capabilities->data.tpmProperties.tpmProperty;
    UINT32 count = capabilities->data.tpmProperties.count;

    if (!count) {
        LOG_ERR("Could not get maximum NV index, try specifying an NV index");
        rc = tool_rc_general_error;
        goto out;
    }

    TPM2_NV_INDEX max = 0;
    UINT32 i;
    for (i=0; i < count; i++) {
        if (properties[i].property == TPM2_PT_NV_INDEX_MAX) {
            max = TPM2_HR_NV_INDEX | properties[i].value;
        }
    }

    if (!max) {
        LOG_ERR("Could not find max NV indices in capabilities");
        rc = tool_rc_general_error;
        goto out;
    }
    /* done getting max NV index */
    free(capabilities);
    capabilities = NULL;

    /* now find what NV indexes are in use */
    rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES, TPM2_NV_INDEX_FIRST,
            TPM2_PT_NV_INDEX_MAX, NULL, &capabilities);
    if (rc != tool_rc_success) {
        goto out;
    }

    /*
     * now starting at the first valid index, find one not in use
     * The TPM interface makes no guarantee that handles are returned in order
     * so we have to do a linear search every attempt for a free handle :-(
     */
    bool found = false;
    TPM2_NV_INDEX choose;
    for (choose = TPM2_HR_NV_INDEX; choose < max; choose++) {
        /* take the index to guess and check against everything in use */
        bool in_use = false;
        for (i = 0; i < capabilities->data.handles.count; i++) {
            TPMI_RH_NV_INDEX index = capabilities->data.handles.handle[i];
            if (index == choose) {
                in_use = true;
                break;
            }
        }

        if (!in_use) {
            /* it's not in use, use the current value of choose */
            found = true;
            break;
        }
    }

    if (!found) {
        LOG_ERR("No free NV index found");
        rc = tool_rc_general_error;
        goto out;
    }

    *chosen = choose;

out:
    free(capabilities);

    return rc;
}

static tool_rc validate_size(ESYS_CONTEXT *ectx) {

    #define TYPICAL_NVINDEX_MAX 2048
    if (ctx.is_tcti_none && !ctx.size_set) {
        ctx.size = TYPICAL_NVINDEX_MAX;
        return tool_rc_success;
    }

    UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.halg);

    switch ((ctx.nv_attribute & TPMA_NV_TPM2_NT_MASK) >> TPMA_NV_TPM2_NT_SHIFT) {
        case TPM2_NT_ORDINARY:
            if (!ctx.size_set) {
                ctx.size = tpm2_nv_util_max_allowed_nv_size(ectx, true);
            }
            break;
        case TPM2_NT_COUNTER:
        case TPM2_NT_BITS:
        case TPM2_NT_PIN_FAIL:
        case TPM2_NT_PIN_PASS:
            if (!ctx.size_set) {
                ctx.size = 8;
            } else if (ctx.size != 8) {
                LOG_ERR("Size is invalid for an NV index type,"
                        " it must be size of 8");
                return tool_rc_general_error;
            }
            break;
        case TPM2_NT_EXTEND:
            if (!ctx.size_set) {
                ctx.size = hash_size;
            } else if (ctx.size != hash_size) {
                LOG_ERR("Size is invalid for an NV index type: \"extend\","
                        " it must match the name hash algorithm size of %"
                        PRIu16, hash_size);
                return tool_rc_general_error;
            }
            break;
    }

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */
    tpm2_session *tmp;
    tool_rc rc = tpm2_auth_util_from_optarg(NULL, ctx.index_auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid index authorization");
        return rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.nv_auth = *auth;

    tpm2_session_close(&tmp);

    /*
     * 1.b Add object names and their auth sessions
     */
    rc = (!ctx.is_tcti_none) ?
        tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P) :

        tpm2_util_object_load(ectx, ctx.auth_hierarchy.ctx_path,
            &ctx.auth_hierarchy.object,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);

    if (rc != tool_rc_success) {
        LOG_ERR("Invalid handle or authorization.");
        return tool_rc_option_error;
    }

    /*
     * 2. Restore auxiliary sessions
     */
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. Command specific initializations dependent on loaded objects
     */
    handle_default_attributes();

    if (!ctx.nv_index) {
        rc = handle_no_index_specified(ectx, &ctx.nv_index);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    rc = validate_size(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    ctx.public_info.nvPublic.nvIndex = ctx.nv_index;
    ctx.public_info.nvPublic.nameAlg = ctx.halg;
    ctx.public_info.nvPublic.attributes = ctx.nv_attribute;
    ctx.public_info.nvPublic.dataSize = ctx.size;

    if (ctx.policy_file) {
        ctx.public_info.nvPublic.authPolicy.size = BUFFER_SIZE(TPM2B_DIGEST,
            buffer);

        bool is_policy_load = files_load_bytes_from_path(ctx.policy_file,
            ctx.public_info.nvPublic.authPolicy.buffer,
            &ctx.public_info.nvPublic.authPolicy.size);
        if (!is_policy_load) {
            return tool_rc_general_error;
        }
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /* 4.a Determine pHash length and alg */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
        ctx.aux_session[0],
        ctx.aux_session[1]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * is_tcti_none       [N]
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.is_tcti_none ||
        (ctx.cp_hash_path && !ctx.rp_hash_path)) ? false : true;

    return rc;
}

static tool_rc check_options(tpm2_option_flags flags) {

    if (!ctx.size && ctx.size_set) {
        LOG_WARN("Defining an index with size 0");
    }

    ctx.is_tcti_none = flags.tcti_none ? true : false;
    if (ctx.is_tcti_none && !ctx.cp_hash_path) {
        LOG_ERR("If tcti is none, then cpHash path must be specified");
        return tool_rc_option_error;
    }

    /*
     * TODO: Add error checking for NV ranges reserved for specific hierarchies
     */

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 's':
        ctx.size_set = true;
        result = tpm2_util_string_to_uint16(value, &ctx.size);
        if (!result) {
            LOG_ERR("Could not convert size to number, got: \"%s\"", value);
            return false;
        }
        break;
    case 'a':
        result = tpm2_util_string_to_uint32(value, &ctx.nv_attribute);
        if (!result) {
            result = tpm2_attr_util_nv_strtoattr(value, &ctx.nv_attribute);
            if (!result) {
                LOG_ERR(
                        "Could not convert NV attribute to number or keyword, got: \"%s\"",
                        value);
                return false;
            }
        }
        break;
    case 'p':
        ctx.index_auth_str = value;
        break;
    case 'L':
        ctx.policy_file = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    case 1:
        ctx.rp_hash_path = value;
        break;
    case 'S':
        ctx.aux_session_path[ctx.aux_session_cnt] = value;
        if (ctx.aux_session_cnt < MAX_AUX_SESSIONS) {
            ctx.aux_session_cnt++;
        } else {
            return false;
        }
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid choice for name digest hash algorithm");
            return false;
        }
        break;
    }

    return true;
}

static bool on_arg(int argc, char **argv) {

    return on_arg_nv_index(argc, argv, &ctx.nv_index);
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "hierarchy",      required_argument, NULL, 'C' },
        { "size",           required_argument, NULL, 's' },
        { "attributes",     required_argument, NULL, 'a' },
        { "hierarchy-auth", required_argument, NULL, 'P' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "index-auth",     required_argument, NULL, 'p' },
        { "policy",         required_argument, NULL, 'L' },
        { "cphash",         required_argument, NULL,  0  },
        { "rphash",         required_argument, NULL,  1  },
        { "session",        required_argument, NULL, 'S' },
    };

    *opts = tpm2_options_new("S:C:s:a:P:p:L:g:", ARRAY_LEN(topts), topts,
        on_option, on_arg, TPM2_OPTIONS_FAKE_TCTI);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options(flags);
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
    rc = nv_space_define(ectx);
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

    /*
     * 2. Close authorization sessions
     */
    tool_rc rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_hierarchy.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * 3. Close auxiliary sessions
     */
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvdefine", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, NULL)
