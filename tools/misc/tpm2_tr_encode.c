/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2_convert.h"
#include "tpm2_identity_util.h"
#include "tpm2_tool.h"

typedef struct tpm2_tr_encode_ctx tpm2_tr_encode_ctx;
struct tpm2_tr_encode_ctx {
    const char *context_arg;
    const char *public_arg;
    const char *output_arg;
};
static tpm2_tr_encode_ctx ctx;

static bool tpm2_util_persistent_to_esys_tr(TPM2_HANDLE handle, TPM2B_PUBLIC *public, TPM2B_NAME *name, uint8_t **tr_buf, size_t *size) {

#define IESYSC_KEY_RSRC 1
    /*
     * So this is the format of an ESYS_TR:
     * 4 bytes TPM2_HANDLE
     * TPM2B_NAME
     * 4 bytes resource type
     * TPM2B_PUBLIC
     */

    /* can only serialize persistent objects */
    if ((handle >> TPM2_HR_SHIFT) != TPM2_HT_PERSISTENT) {
        LOG_ERR("Handle must be persistent, got: 0x%x", handle);
        return false;
    }

    /* Step 1 calculate the size */
    size_t buf_size = SIZE_MAX;
    size_t offset = 0;
    void *buffer = NULL;
    for (unsigned i=0; i < 2; i++) {
        TSS2_RC rc = Tss2_MU_TPM2_HANDLE_Marshal(
            handle,
            buffer,
            buf_size,
            &offset);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_MU_TPM2_HANDLE_Marshal, rc);
            free(buffer);
            return false;
        }

        rc = Tss2_MU_TPM2B_NAME_Marshal(
            name,
            buffer,
            buf_size,
            &offset);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_MU_TPM2B_NAME_Marshal, rc);
            free(buffer);
            return false;
        }

        rc = Tss2_MU_UINT32_Marshal(
            IESYSC_KEY_RSRC,
            buffer,
            buf_size,
            &offset);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_MU_UINT32_Marshal, rc);
            free(buffer);
            return false;
        }

        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
            public,
            buffer,
            buf_size,
            &offset);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_MU_TPM2B_PUBLIC_Marshal, rc);
            free(buffer);
            return false;
        }

        /*
         * on the first time through allocate the buffer for population on
         * the next loop
         */
        if (i == 0) {
            buf_size = offset;
            offset = 0;
            buffer = calloc(1, buf_size);
            if (!buffer) {
                return 1;
            }
        }
    }

    *size = offset;
    *tr_buf = buffer;

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'u':
        ctx.public_arg = value;
        break;
    case 'o':
        ctx.output_arg = value;
        break;

    }
    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
    const struct option topts[] = {
            { "object-context", required_argument, NULL, 'c' },
            { "public",         required_argument, NULL, 'u' },
            { "output",         required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("c:u:o:", ARRAY_LEN(topts), topts, on_option,
          NULL, TPM2_OPTIONS_NO_SAPI);
    return *opts != NULL;
}

static bool check_options(void) {

    bool result = true;

    if (!ctx.context_arg) {
        LOG_ERR("Object Handle must be specified by option \"-c\"");
        result = false;
    }

    if (!ctx.public_arg) {
        LOG_ERR("Objects expected TPM2B_PUBLIC must be specified by option \"-u\"");
        result = false;
    }

    if (!ctx.output_arg) {
        LOG_ERR("The output file for the generated serialized ESYS_TR must be specified by option \"-o\"");
        result = false;
    }

    return result;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);
    UNUSED(ectx);

    bool result = check_options();
    if (!result) {
        return tool_rc_option_error;
    }

    TPMI_RH_PROVISION handle;
    result = tpm2_util_handle_from_optarg(ctx.context_arg, &handle, TPM2_HANDLES_FLAGS_PERSISTENT);
    if (!result) {
        return tool_rc_option_error;
    }

    TPM2B_PUBLIC pub = { 0 };
    result = files_load_public(ctx.public_arg, &pub);
    if (!result) {
        LOG_ERR("Failed to load public key \"%s\"", ctx.public_arg);
        return tool_rc_option_error;
    }

    /* calculate the name */
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    result = tpm2_identity_create_name(&pub, &name);
    if (!result) {
        LOG_ERR("Failed to calculate name");
        return tool_rc_general_error;
    }

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    result = tpm2_util_persistent_to_esys_tr(handle, &pub, &name, &buf, &buf_size);
    if (!result) {
        LOG_ERR("Could not convert to serialized ESYS_TR");
        return tool_rc_general_error;
    }

    result = files_save_bytes_to_file(ctx.output_arg, buf,
            buf_size);
    free(buf);

    return result ? tool_rc_success : tool_rc_general_error;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("tr_encode", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
