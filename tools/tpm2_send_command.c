/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <tcti/tcti_socket.h>

#include "files.h"
#include "main.h"
#include "tpm2-header.h"
#include "log.h"

static bool read_command_from_file(FILE *f, tpm2_command_header **c,
        UINT32 *size) {

    UINT8 tmp[TPM2_COMMAND_HEADER_SIZE];

    size_t ret = fread(tmp, TPM2_COMMAND_HEADER_SIZE, 1, f);
    if (ret != 1 && ferror(f)) {
        LOG_ERR("Failed to read command header: %s", strerror (errno));
        return false;
    }

    UINT32 command_size = get_command_size(tmp, true);
    UINT32 data_size = get_command_size(tmp, false);

    tpm2_command_header *command = (tpm2_command_header *) malloc(command_size);
    if (!command) {
        LOG_ERR("oom");
        return false;
    }

    /* copy the header into the struct */
    memcpy(command, tmp, sizeof(tmp));

    LOG_INFO("command tag:  0x%04x", get_command_tag(tmp));
    LOG_INFO("command size: 0x%08x", command_size);
    LOG_INFO("command code: 0x%08x", get_command_code(tmp));

    ret = fread(command->data, data_size, 1, f);
    if (ret != 1 && ferror(f)) {
        LOG_ERR("Failed to read command body: %s", strerror (errno));
        free(command);
        return false;
    }

    *c = command;
    *size = command_size;

    return true;
}

static bool write_response_to_file(FILE *f, UINT8 *rbuf) {

    tpm2_response_header *r = tpm2_response_header_from_bytes(rbuf);

    UINT32 size = get_response_size(r->bytes, true);

    LOG_INFO("response tag:  0x%04x", get_response_tag(r->bytes));
    LOG_INFO("response size: 0x%08x", size);
    LOG_INFO("response code: 0x%08x", get_response_code(r->bytes));

    return files_write_bytes(f, r->bytes, size);
}
/*
 * This program reads a TPM command buffer from stdin then dumps it out
 * to a tabd TCTI. It then reads the response from the TCTI and writes it
 * to stdout. Like the TCTI, we expect the input TPM command buffer to be
 * in network byte order (big-endian). We output the response in the same
 * form.
 */
int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {
    (void) envp;
    (void) opts;
    (void) argc;
    (void) argv;

    int ret = 1;

    UINT32 size;
    tpm2_command_header *command;
    bool res = read_command_from_file(stdin, &command, &size);
    if (!res) {
        LOG_ERR("failed to read TPM2 command buffer from stdin");
        return ret;
    }

    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_RC rc = Tss2_Sys_GetTctiContext(sapi_context, &tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Failed to get TCTI context from SAPI context: 0x%x", rc);
        goto out;
    }

    rc = tss2_tcti_transmit(tcti_context, size, command->bytes);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("tss2_tcti_transmit failed: 0x%x", rc);
        goto out;
    }

    size_t rsize = TPM2_MAX_SIZE;
    UINT8 rbuf[TPM2_MAX_SIZE];
    rc = tss2_tcti_receive(tcti_context, &rsize, rbuf, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("tss2_tcti_receive failed: 0x%x", rc);
        goto out;
    }

    /*
     * The response buffer, rbuf, all fields are in big-endian, and we save
     * in big-endian.
     */
    bool result = write_response_to_file(stdout, rbuf);
    if (!result) {
        LOG_ERR("Failed writing response to stdout.");
    }

    ret = 0;

    out: free(command);
    return ret;
}
