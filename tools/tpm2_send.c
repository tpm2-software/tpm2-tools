/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_header.h"
#include "tpm2_tool.h"

typedef struct tpm2_send_ctx tpm2_send_ctx;
struct tpm2_send_ctx {
    FILE *input;
    FILE *output;
    tpm2_command_header *command;
};

typedef void (*sighandler_t)(int);

static tpm2_send_ctx ctx;

static void sig_handler(int signum) {
    UNUSED(signum);

    exit (tool_rc_success);
}

static int read_command_from_file(FILE *f, tpm2_command_header **c,
        UINT32 *size) {

    UINT8 buffer[TPM2_COMMAND_HEADER_SIZE];

    size_t ret = fread(buffer, TPM2_COMMAND_HEADER_SIZE, 1, f);
    if (ret != 1 && ferror(f) && errno != EINTR) {
        LOG_ERR("Failed to read command header: %s", strerror (errno));
        return -1;
    }

    if (feof(f) || ferror(f)) {
        return 0;
    }

    const tpm2_command_header *header = tpm2_command_header_from_bytes(buffer);

    UINT32 command_size = tpm2_command_header_get_size(header, true);
    UINT32 data_size = tpm2_command_header_get_size(header, false);

    if (command_size > TPM2_MAX_SIZE || command_size < data_size) {
        LOG_ERR("Command buffer %"PRIu32" bytes cannot be smaller then the "
                "encapsulated data %"PRIu32" bytes, and can not be bigger than"
                " the maximum buffer size", command_size, data_size);
        return -1;
    }

    tpm2_command_header *command = (tpm2_command_header *) malloc(command_size);
    if (!command) {
        LOG_ERR("oom");
        return -1;
    }

    /* copy the header into the struct */
    memcpy(command, buffer, sizeof(buffer));

    LOG_INFO("command tag:  0x%04x", tpm2_command_header_get_tag(command));
    LOG_INFO("command size: 0x%08x", command_size);
    LOG_INFO("command code: 0x%08x", tpm2_command_header_get_code(command));

    ret = fread(command->data, data_size, 1, f);
    if (ret != 1) {
        LOG_ERR("Failed to read command body: %s", feof(f) ? "EOF" : strerror (errno));
        free(command);
        return -1;
    }

    *c = command;
    *size = command_size;

    return 1;
}

static bool write_response_to_file(FILE *f, UINT8 *rbuf) {

    const tpm2_response_header *r = tpm2_response_header_from_bytes(rbuf);

    UINT32 size = tpm2_response_header_get_size(r, true);

    LOG_INFO("response tag:  0x%04x", tpm2_response_header_get_tag(r));
    LOG_INFO("response size: 0x%08x", size);
    LOG_INFO("response code: 0x%08x", tpm2_response_header_get_code(r));

    bool rc =  files_write_bytes(f, r->bytes, size);
    fflush(f);
    return rc;
}

static FILE *open_file(const char *path, const char *mode) {
    FILE *f = fopen(path, mode);
    if (!f) {
        LOG_ERR("Could not open \"%s\", error: \"%s\"", path, strerror(errno));
    }
    return f;
}

static void close_file(FILE *f) {

    if (f && (f != stdin || f != stdout)) {
        fclose(f);
    }
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'o':
        ctx.output = open_file(value, "wb");
        if (!ctx.output) {
            return false;
        }
        break;
        /* no break */
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Expected 1 tpm buffer input file, got: %d", argc);
        return false;
    }

    ctx.input = fopen(argv[0], "rb");
    if (!ctx.input) {
        LOG_ERR("Error opening file \"%s\", error: %s", argv[0],
                strerror(errno));
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "output", required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("o:", ARRAY_LEN(topts), topts, on_option, on_args,
            0);

    ctx.input = stdin;
    ctx.output = stdout;

    return *opts != NULL;
}

/*
 * This program reads a TPM command buffer from stdin then dumps it out
 * to a tabd TCTI. It then reads the response from the TCTI and writes it
 * to stdout. Like the TCTI, we expect the input TPM command buffer to be
 * in network byte order (big-endian). We output the response in the same
 * form.
 */
static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    sighandler_t old_handler = signal(SIGINT, sig_handler);
    if(old_handler == SIG_ERR) {
        LOG_WARN("Could not set SIGINT handler: %s", strerror(errno));
    }

    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_RC rval = Esys_GetTcti(context, &tcti_context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetTctiContext, rval);
        return tool_rc_from_tpm(rval);
    }

    while (1) {
        UINT32 size;
        int result = read_command_from_file(ctx.input, &ctx.command, &size);
        if (result < 0) {
            LOG_ERR("failed to read TPM2 command buffer from file");
            return tool_rc_general_error;
        } else if (result == 0) {
            return tool_rc_success;
        }

        rval = Tss2_Tcti_Transmit(tcti_context, size, ctx.command->bytes);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("tss2_tcti_transmit failed: 0x%x", rval);
            return tool_rc_from_tpm(rval);
        }

        size_t rsize = TPM2_MAX_SIZE;
        UINT8 rbuf[TPM2_MAX_SIZE];
        rval = Tss2_Tcti_Receive(tcti_context, &rsize, rbuf,
                TSS2_TCTI_TIMEOUT_BLOCK);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("tss2_tcti_receive failed: 0x%x", rval);
            return tool_rc_from_tpm(rval);
        }

        /*
         * The response buffer, rbuf, all fields are in big-endian, and we save
         * in big-endian.
         */
        result = write_response_to_file(ctx.output, rbuf);
        if (!result) {
            LOG_ERR("Failed writing response to output file.");
            return tool_rc_general_error;
        }

        free(ctx.command);
        ctx.command = NULL;
    }

    /* shouldn't be possible */
    return tool_rc_success;
}

static void tpm2_tool_onexit(void) {

    close_file(ctx.input);
    close_file(ctx.output);

    free(ctx.command);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("send", tpm2_tool_onstart, tpm2_tool_onrun, NULL, tpm2_tool_onexit)
