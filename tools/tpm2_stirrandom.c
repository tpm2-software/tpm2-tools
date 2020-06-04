/* SPDX-License-Identifier: BSD-3-Clause */

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

/* Spec enforce input data to be not longer than 128 bytes */
#define MAX_SIZE_TO_READ 128

typedef struct tpm_stirrandom_ctx tpm_stirrandom_ctx;
struct tpm_stirrandom_ctx {
    TPM2B_SENSITIVE_DATA in_data;
    char *in_file;
};

static tpm_stirrandom_ctx ctx = {
        .in_data = { .size = MAX_SIZE_TO_READ }
};

static bool on_args(int argc, char **argv) {

    if (argc != 1) {
        LOG_ERR("Only supports one FILE_INPUT file, got %d arguments", argc);
        return false;
    }

    ctx.in_file = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    *opts = tpm2_options_new(NULL, 0, NULL, NULL, on_args, 0);

    return *opts != NULL;
}

static bool load_sensitive(void) {

    bool res = files_load_bytes_from_buffer_or_file_or_stdin(NULL, ctx.in_file,
            &ctx.in_data.size, ctx.in_data.buffer);
    if (!res) {
        LOG_ERR("Error while reading data from file or stdin");
        return false;
    }

    if (ctx.in_data.size == 0) {
        LOG_ERR("Data size to send is zero");
        return false;
    }

    LOG_INFO("Submitting %d bytes to TPM", ctx.in_data.size);

    return true;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!load_sensitive()) {
        return tool_rc_general_error;
    }

    return tpm2_stirrandom(ectx, &ctx.in_data);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("stirrandom", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
