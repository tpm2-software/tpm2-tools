/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdbool.h>
#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

typedef struct tpm_nvdefine_ctx tpm_nvdefine_ctx;
struct tpm_nvdefine_ctx {
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

    char *policy_file;
    char *index_auth_str;

    char *cp_hash_path;
};

static tpm_nvdefine_ctx ctx = {
    .auth_hierarchy = {
        .ctx_path = "o",
    },
    .nv_auth = TPM2B_EMPTY_INIT,
};

static tool_rc nv_space_define(ESYS_CONTEXT *ectx) {

    TPM2B_NV_PUBLIC public_info = TPM2B_EMPTY_INIT;

    public_info.nvPublic.nvIndex = ctx.nv_index;
    public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;

    // Now set the attributes.
    public_info.nvPublic.attributes = ctx.nv_attribute;

    if (!ctx.size) {
        LOG_WARN("Defining an index with size 0");
    }

    if (ctx.policy_file) {
        public_info.nvPublic.authPolicy.size = BUFFER_SIZE(TPM2B_DIGEST,
                buffer);
        if (!files_load_bytes_from_path(ctx.policy_file,
                public_info.nvPublic.authPolicy.buffer,
                &public_info.nvPublic.authPolicy.size)) {
            return tool_rc_general_error;
        }
    }

    public_info.nvPublic.dataSize = ctx.size;

    tool_rc rc = tool_rc_success;
    if (!ctx.cp_hash_path) {
        rc = tpm2_nv_definespace(ectx, &ctx.auth_hierarchy.object,
                &ctx.nv_auth, &public_info, NULL);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to create NV index 0x%x.", ctx.nv_index);
            return rc;
        }
        tpm2_tool_output("nv-index: 0x%x\n", ctx.nv_index);
        goto nvdefine_out;
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = tpm2_nv_definespace(ectx, &ctx.auth_hierarchy.object,
        &ctx.nv_auth, &public_info, &cp_hash);;
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }

nvdefine_out:
    return rc;
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
        { "index-auth",     required_argument, NULL, 'p' },
        { "policy",         required_argument, NULL, 'L' },
        { "cphash",         required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:s:a:P:p:L:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
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
        ctx.nv_attribute |= TPMA_NV_PPWRITE | TPMA_NV_PPREAD;
    } /* else it's an nv index for auth */

    /* if it has a policy file, set policy read and write vs auth read and write */
    if (ctx.policy_file) {
        ctx.nv_attribute |= TPMA_NV_POLICYWRITE | TPMA_NV_POLICYREAD;
    } else {
        ctx.nv_attribute |= TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD;
    }
}

static void get_max_nv_index_size(ESYS_CONTEXT *ectx, UINT16 *size) {

    *size = 0;

    /* get the max NV index for the TPM */
    TPMS_CAPABILITY_DATA *capabilities = NULL;
    tool_rc tmp_rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED,
            TPM2_MAX_TPM_PROPERTIES, NULL, &capabilities);
    if (tmp_rc != tool_rc_success) {
        *size = TPM2_MAX_NV_BUFFER_SIZE;
        LOG_ERR("Could not get fixed TPM properties");
        return;
    }

    TPMS_TAGGED_PROPERTY *properties = capabilities->data.tpmProperties.tpmProperty;
    UINT32 count = capabilities->data.tpmProperties.count;

    if (!count) {
        *size = TPM2_MAX_NV_BUFFER_SIZE;
        LOG_ERR("Could not get maximum NV index size");
        goto out;
    }

    UINT32 i;
    for (i=0; i < count; i++) {
        if (properties[i].property == TPM2_PT_NV_INDEX_MAX) {
            *size = properties[i].value;
            break;
        }
    }

    if (*size == 0) {
        *size = TPM2_MAX_NV_BUFFER_SIZE;
        LOG_ERR("Could not find max NV indices in capabilities");
    }

out:
    free(capabilities);

    return;
}

static tool_rc handle_no_index_specified(ESYS_CONTEXT *ectx, TPM2_NV_INDEX *chosen) {

    tool_rc rc = tool_rc_general_error;

    TPM2_NV_INDEX max = 0;

    /* get the max NV index for the TPM */
    TPMS_CAPABILITY_DATA *capabilities = NULL;
    tool_rc tmp_rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED,
            TPM2_MAX_TPM_PROPERTIES, NULL, &capabilities);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }

    TPMS_TAGGED_PROPERTY *properties = capabilities->data.tpmProperties.tpmProperty;
    UINT32 count = capabilities->data.tpmProperties.count;

    if (!count) {
        LOG_ERR("Could not get maximum NV index, try specifying an NV index");
        goto out;
    }

    UINT32 i;
    for (i=0; i < count; i++) {
        if (properties[i].property == TPM2_PT_NV_INDEX_MAX) {
            max = TPM2_HR_NV_INDEX | properties[i].value;
        }
    }

    if (!max) {
        LOG_ERR("Could not find max NV indices in capabilities");
        goto out;
    }

    /* done getting max NV index */
    free(capabilities);
    capabilities = NULL;

    /* now find what NV indexes are in use */
    tmp_rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES, tpm2_util_hton_32(TPM2_HT_NV_INDEX),
            TPM2_PT_NV_INDEX_MAX, NULL, &capabilities);
    if (tmp_rc != tool_rc_success) {
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

        bool in_use = false;

        /* take the index to guess and check against everything in use */
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
        goto out;
    }

    *chosen = choose;

    rc = tool_rc_success;

out:
    free(capabilities);

    return rc;
}

static tool_rc validate_size(ESYS_CONTEXT *ectx) {

    switch ((ctx.nv_attribute & TPMA_NV_TPM2_NT_MASK) >> TPMA_NV_TPM2_NT_SHIFT) {
        case TPM2_NT_ORDINARY:
            if (!ctx.size_set) {
                get_max_nv_index_size(ectx, &ctx.size);
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
                // Currently the NV define doesn't allow changing name algorithm, so this OK
                ctx.size = TPM2_SHA256_DIGEST_SIZE;
            } else if (ctx.size != TPM2_SHA256_DIGEST_SIZE) {
                LOG_ERR("Size is invalid for an NV index type: \"extend\","
                        " it must match the name hash algorithm size of 32");
                return tool_rc_general_error;
            }
            break;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid authorization");
        return rc;
    }

    tpm2_session *tmp;
    rc = tpm2_auth_util_from_optarg(NULL, ctx.index_auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid index authorization");
        return rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.nv_auth = *auth;

    tpm2_session_close(&tmp);

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

    return nv_space_define(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    if (!ctx.cp_hash_path) {
        return tpm2_session_close(&ctx.auth_hierarchy.object.session);
    }
    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("nvdefine", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
