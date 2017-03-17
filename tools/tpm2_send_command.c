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

#include "main.h"
#include "tpm2-header.h"
#include "log.h"

#define MAX_BUF 4096
#define COMMAND_HEADER_SIZE (sizeof (TPMI_ST_COMMAND_TAG) + sizeof (UINT32) + sizeof (TPM_CC))
#define RESPONSE_HEADER_SIZE (sizeof (TPM_ST) + sizeof (UINT32) + sizeof (TPM_RC))

/*
 * Read a TPM command buffer from a 'file_stream'. Store this buffer in
 * 'buf'. On success we return the size of the command, error returns 0.
 */
UINT32
read_command_from_file (FILE              *file_stream,
                        uint8_t           *buf,
                        size_t const       buf_size)
{
    size_t ret;
    UINT32 command_size;

    LOG_INFO ("read_command_from_file");
    ret = fread (buf, COMMAND_HEADER_SIZE, 1, file_stream);
    /* I'm not sure if fread will actually set errno from the docs */
    if (ret != 1 && ferror (file_stream)) {
        LOG_ERR ("Failed to read command header: %s",
                 strerror (errno));
        return 0;
    }
    LOG_INFO ("read %zd command header of size: %zd",
                 ret, COMMAND_HEADER_SIZE);
    command_size = get_command_size (buf);
    if (command_size > buf_size) {
        LOG_ERR("buf_size is insufficient: %u > %zd",
                 command_size, buf_size);
        return 0;
    }
    LOG_INFO ("command tag:  0x%04x", get_command_tag  (buf));
    LOG_INFO ("command size: 0x%08x", get_command_size (buf));
    LOG_INFO ("command code: 0x%08x", get_command_code (buf));
    ret = fread (buf + COMMAND_HEADER_SIZE,
                 command_size - COMMAND_HEADER_SIZE,
                 1,
                 file_stream);
    if (ret != 1 && ferror (file_stream)) {
        LOG_ERR ("Failed to read command body: %s",
                 strerror (errno));
        return 0;
    }
    LOG_INFO ("read command body successfully");
    return command_size;
}
/*
 * Write a TPM response buffer to a 'file_stream'. On error this function
 * returns 0, on success it returns the size of the response buffer.
 */
UINT32
write_response_to_file (FILE           *file_stream,
                        uint8_t        *buf,
                        size_t const    buf_size)
{
    size_t num_write;
    UINT32 response_size;

    LOG_INFO ("write_response_to_file");
    num_write = fwrite (buf, RESPONSE_HEADER_SIZE, 1, file_stream);
    if (num_write != 1 && ferror (stdout)) {
        LOG_ERR ("failed to write to stdout");
        return 0;
    }
    LOG_INFO ("wrote response header: %zd members of size %zd",
                 num_write, RESPONSE_HEADER_SIZE);
    response_size = get_command_size (buf);
    if (response_size > buf_size) {
        LOG_ERR ("buf_size is insufficient: %u > %zd",
                 response_size, buf_size);
        return 0;
    }
    LOG_INFO ("response tag:  0x%04x", get_response_tag  (buf));
    LOG_INFO ("response size: 0x%08x", get_response_size (buf));
    LOG_INFO ("response code: 0x%08x", get_response_code (buf));

    num_write = fwrite (buf + RESPONSE_HEADER_SIZE,
                        response_size - RESPONSE_HEADER_SIZE,
                        1,
                        file_stream);
    if (num_write != 1 && ferror (file_stream)) {
        LOG_ERR ("Failed to write response to file: %s",
                 strerror (errno));
        return 0;

    }
    LOG_INFO ("wrote response body: %zd members of size 0x%x",
                 num_write, response_size);
    return response_size;
}
/*
 * This program reads a TPM command buffer from stdin then dumps it out
 * to a tabd TCTI. It then reads the response from the TCTI and writes it
 * to stdout. Like the TCTI, we expect the input TPM command buffer to be
 * in network byte order (big-endian). We output the response in the same
 * form.
 */
int
execute_tool (int              argc,
             char             *argv[],
             char             *envp[],
             common_opts_t    *opts,
             TSS2_SYS_CONTEXT *sapi_context)
{
    (void)envp;
    (void)opts;
    (void)argc;
    (void)argv;

    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    size_t response_size = MAX_BUF;
    uint8_t buf [MAX_BUF];
    UINT32 written_size, command_size;
    TSS2_RC rc;

    command_size = read_command_from_file (stdin, buf, MAX_BUF);
    if (command_size == 0) {
        LOG_ERR ("failed to read TPM2 command buffer from stdin");
        return 1;
    }

    rc = Tss2_Sys_GetTctiContext (sapi_context, &tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR ("Failed to get TCTI context from SAPI context: 0x%x",
                 rc);
        return 1;
    }
    rc = tss2_tcti_transmit (tcti_context, command_size, buf);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR ("tss2_tcti_transmit failed: 0x%x", rc);
        return 1;
    }
    rc = tss2_tcti_receive (tcti_context,
                            &response_size,
                            buf,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR ("tss2_tcti_receive failed: 0x%x", rc);
        return 1;
    }
    written_size = write_response_to_file (stdout, buf, response_size);
    if (written_size < response_size) {
        LOG_ERR ("write_command_to_file failed");
        return 1;
    }
    return 0;
}
