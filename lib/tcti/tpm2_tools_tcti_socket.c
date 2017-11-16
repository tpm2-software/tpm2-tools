//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
#include <inttypes.h>
#include <stdlib.h>

#include <tcti/tcti_socket.h>
#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_tools_tcti_socket.h"
#include "tpm2_util.h"

#define TCTI_SOCKET_DEFAULT_ADDRESS "127.0.0.1"
#define TCTI_SOCKET_DEFAULT_PORT     2321

#define TPM2TOOLS_ENV_SOCKET_ADDRESS "TPM2TOOLS_SOCKET_ADDRESS"
#define TPM2TOOLS_ENV_SOCKET_PORT    "TPM2TOOLS_SOCKET_PORT"

TSS2_TCTI_CONTEXT*
tpm2_tools_tcti_socket_init (char *opts)
{
    TCTI_SOCKET_CONF conf = {
        .hostname          = TCTI_SOCKET_DEFAULT_ADDRESS,
        .port              = TCTI_SOCKET_DEFAULT_PORT,
        .logCallback       = NULL,
        .logBufferCallback = NULL,
        .logData           = NULL,
    };

    char *addr_env = getenv(TPM2TOOLS_ENV_SOCKET_ADDRESS);
    if (addr_env) {
        conf.hostname = addr_env;
    }

    char *port_env = getenv(TPM2TOOLS_ENV_SOCKET_PORT);
    if (port_env) {
        bool res = tpm2_util_string_to_uint16(port_env, &conf.port);
        if (!res) {
            LOG_ERR("Error getting env var\""TPM2TOOLS_ENV_SOCKET_PORT"\","
                    "got: \"%s\", expected a number!", port_env);
            return NULL;
        }
    }

    /* opts should be something like: "hostname:port" */
    if (opts) {
        char *port_sep = strrchr(opts, ':');
        if (port_sep) {
            port_sep[0] = '\0';
            port_sep++;
            bool res = tpm2_util_string_to_uint16(port_sep, &conf.port);
            if (!res) {
                LOG_ERR("Error getting env var\""TPM2TOOLS_ENV_SOCKET_PORT"\","
                        "got: \"%s\", expected a number!", port_sep);
                return NULL;
            }
        }
        conf.hostname = opts;
    }

    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = InitSocketTcti (NULL, &size, &conf, 0);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Faled to get allocation size for tcti context: "
                 "0x%x", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*)calloc (1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR("Allocation for tcti context failed: oom");
        return NULL;
    }
    rc = InitSocketTcti (tcti_ctx, &size, &conf, 0);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to initialize tcti context: 0x%x\n", rc);
        free (tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
