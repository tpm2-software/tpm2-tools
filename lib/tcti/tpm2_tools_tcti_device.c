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

#include <sapi/tpm20.h>
#include <tcti/tcti_device.h>

#include "log.h"
#include "tpm2_tools_tcti_device.h"
#include "tpm2_util.h"

#define TPM2TOOLS_ENV_DEVICE_FILE "TPM2TOOLS_DEVICE_FILE"
#define TCTI_DEVICE_DEFAULT_PATH  "/dev/tpm0"

TSS2_TCTI_CONTEXT *tpm2_tools_tcti_device_init(char *opts) {

    TCTI_DEVICE_CONF conf = {
        .device_path = TCTI_DEVICE_DEFAULT_PATH,
    };

    char *env_path = getenv(TPM2TOOLS_ENV_DEVICE_FILE);
    if (env_path) {
        conf.device_path = env_path;
    }

    if (opts) {
        conf.device_path = opts;
    }

    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = InitDeviceTcti(NULL, &size, 0);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to get allocation size for device tcti context: "
                 "0x%x", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR("Allocation for device TCTI context failed: oom");
        return NULL;
    }
    rc = InitDeviceTcti(tcti_ctx, &size, &conf);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to initialize device TCTI context: 0x%x", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
