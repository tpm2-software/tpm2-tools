/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_capability.h"
#include "tpm2_tool.h"

typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_hierarchy;

    struct {
        char *ctx_path;
        tpm2_loaded_object object;
    } to_persist_key;

    TPMI_DH_PERSISTENT persist_handle;

    const char *output_arg;

    struct {
        UINT8 p :1;
        UINT8 c :1;
        UINT8 o :1;
    } flags;
    char *cp_hash_path;
};

static tpm_evictcontrol_ctx ctx = {
    .auth_hierarchy.ctx_path="o",
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.auth_hierarchy.ctx_path = value;
        break;
    case 'P':
        ctx.auth_hierarchy.auth_str = value;
        break;
    case 'c':
        ctx.to_persist_key.ctx_path = value;
        ctx.flags.c = 1;
        break;
    case 'o':
        ctx.output_arg = value;
        ctx.flags.o = 1;
        break;
    case 0:
        ctx.cp_hash_path = value;
        break;
    }

    return true;
}

static bool on_arg(int argc, char *argv[]) {

    if (argc > 1) {
        LOG_ERR("Expected at most one persistent handle, got %d", argc);
        return false;
    }

    const char *value = argv[0];

    bool result = tpm2_util_string_to_uint32(value, &ctx.persist_handle);
    if (!result) {
        LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
                value);
        return false;
    }
    ctx.flags.p = 1;

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "hierarchy",      required_argument, NULL, 'C' },
      { "auth",           required_argument, NULL, 'P' },
      { "object-context", required_argument, NULL, 'c' },
      { "output",         required_argument, NULL, 'o' },
      { "cphash",         required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("C:P:c:o:", ARRAY_LEN(topts), topts, on_option,
            on_arg, 0);

    return *opts != NULL;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = tool_rc_general_error;
    bool evicted = false;

    /* load up the object/handle to work on */
    tool_rc tmp_rc = tpm2_util_object_load(ectx, ctx.to_persist_key.ctx_path,
            &ctx.to_persist_key.object, TPM2_HANDLE_ALL_W_NV);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out;
    }

    /* load up the auth hierarchy */
    tmp_rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out;
    }

    if (ctx.to_persist_key.object.handle >> TPM2_HR_SHIFT
            == TPM2_HT_PERSISTENT) {
        ctx.persist_handle = ctx.to_persist_key.object.handle;
        ctx.flags.p = 1;
    }

    /* If we've been given a handle or context object to persist and not an
     * explicit persistent handle to use, find an available vacant handle in
     * the persistent namespace and use that.
     *
     * XXX: We need away to figure out of object is persistent and skip it.
     */
    if (ctx.flags.c && !ctx.flags.p) {
        bool is_platform = ctx.auth_hierarchy.object.handle == TPM2_RH_PLATFORM;
        tmp_rc = tpm2_capability_find_vacant_persistent_handle(ectx,
                is_platform, &ctx.persist_handle);
        if (tmp_rc != tool_rc_success) {
            rc = tmp_rc;
            goto out;
        }
        /* we searched and found a persistent handle, so mark that peristent handle valid */
        ctx.flags.p = 1;
    }

    if (ctx.flags.o && !ctx.flags.p) {
        LOG_ERR("Cannot specify -o without using a persistent handle");
        goto out;
    }

    ESYS_TR out_tr;
    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        LOG_WARN("Calculating cpHash. Exiting without evicting objects.");
        tool_rc rc = tpm2_evictcontrol(ectx, &ctx.auth_hierarchy.object,
        &ctx.to_persist_key.object, ctx.persist_handle, &out_tr, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }
        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }
        return rc;
    }

    /*
     * ESAPI is smart enough that if the object is persistent, to ignore the argument
     * for persistent handle. Thus we can use ESYS_TR output to determine if it's
     * evicted or not.
     */
    rc = tpm2_evictcontrol(ectx, &ctx.auth_hierarchy.object,
            &ctx.to_persist_key.object, ctx.persist_handle, &out_tr, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    /*
     * Only Close a TR object if it's still resident in the TPM.
     * When these handles match, evictcontrol flushed it from the TPM.
     * It's evicted when ESAPI sends back a none handle on evictcontrol.
     *
     * XXX: This output is wrong because we can't determine what handle was
     * evicted on ESYS_TR input.
     *
     * See bug: https://github.com/tpm2-software/tpm2-tools/issues/1816
     */
    evicted = out_tr == ESYS_TR_NONE;
    tpm2_tool_output("persistent-handle: 0x%x\n", ctx.persist_handle);
    tpm2_tool_output("action: %s\n", evicted ? "evicted" : "persisted");

    if (ctx.output_arg) {
        rc = files_save_ESYS_TR(ectx, out_tr, ctx.output_arg);
    } else {
        rc = tool_rc_success;
    }

out:
    if (!evicted) {
        rc = tpm2_close(ectx, &out_tr);
    }

    return rc;
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    return tpm2_session_close(&ctx.auth_hierarchy.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("evictcontrol", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
