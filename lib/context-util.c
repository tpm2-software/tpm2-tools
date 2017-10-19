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
#include <inttypes.h>
#include <string.h>
#ifdef HAVE_TCTI_DEV
#include <tcti/tcti_device.h>
#endif
#ifdef HAVE_TCTI_SOCK
#include <tcti/tcti_socket.h>
#endif
#ifdef HAVE_TCTI_TABRMD
#include <tcti/tcti-tabrmd.h>
#endif

#include "context-util.h"
#include "log.h"

/*
 * Initialize a TSS2_TCTI_CONTEXT for the device TCTI.
 */
#ifdef HAVE_TCTI_DEV
TSS2_TCTI_CONTEXT*
tcti_device_init (char const *device_file)
{
    TCTI_DEVICE_CONF conf = {
        .device_path = device_file,
        .logCallback = NULL,
        .logData     = NULL,
    };
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = InitDeviceTcti (NULL, &size, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf (stderr,
                 "Failed to get allocation size for device tcti context: "
                 "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*)calloc (1, size);
    if (tcti_ctx == NULL) {
        fprintf (stderr,
                 "Allocation for device TCTI context failed: %s\n",
                 strerror (errno));
        return NULL;
    }
    rc = InitDeviceTcti (tcti_ctx, &size, &conf);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf (stderr,
                 "Failed to initialize device TCTI context: 0x%x\n",
                 rc);
        free (tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
#endif
/*
 * Initialize a socket TCTI instance using the provided options structure.
 * The address and port are the only configuration options used. Callbacks
 * for logging are set to NULL.
 * The caller is returned a TCTI context structure that is allocated by this
 * function. This structure must be freed by the caller.
 */
#ifdef HAVE_TCTI_SOCK
TSS2_TCTI_CONTEXT*
tcti_socket_init (char const *address,
                  uint16_t    port)
{
    TCTI_SOCKET_CONF conf = {
        .hostname          = address,
        .port              = port,
        .logCallback       = NULL,
        .logBufferCallback = NULL,
        .logData           = NULL,
    };
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = InitSocketTcti (NULL, &size, &conf, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf (stderr, "Faled to get allocation size for tcti context: "
                 "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*)calloc (1, size);
    if (tcti_ctx == NULL) {
        fprintf (stderr, "Allocation for tcti context failed: %s\n",
                 strerror (errno));
        return NULL;
    }
    rc = InitSocketTcti (tcti_ctx, &size, &conf, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf (stderr, "Failed to initialize tcti context: 0x%x\n", rc);
        free (tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
#endif
#ifdef HAVE_TCTI_TABRMD
TSS2_TCTI_CONTEXT*
tcti_tabrmd_init (void)
{
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_RC rc;
    size_t size;

    rc = tss2_tcti_tabrmd_init(NULL, &size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR ("Failed to get size for TABRMD TCTI context: 0x%" PRIx32, rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*)calloc (1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR ("Allocation for TABRMD TCTI context failed: %s",
                 strerror (errno));
        return NULL;
    }
    rc = tss2_tcti_tabrmd_init (tcti_ctx, &size);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR ("Failed to initialize TABRMD TCTI context: 0x%" PRIx32, rc);
        free (tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}
#endif
/*
 * Initialize a SAPI context using the TCTI context provided by the caller.
 * This function allocates memory for the SAPI context and returns it to the
 * caller. This memory must be freed by the caller.
 */
static TSS2_SYS_CONTEXT*
sapi_ctx_init (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    TSS2_SYS_CONTEXT *sapi_ctx;
    TSS2_RC rc;
    size_t size;
    TSS2_ABI_VERSION abi_version = {
        .tssCreator = TSSWG_INTEROP,
        .tssFamily  = TSS_SAPI_FIRST_FAMILY,
        .tssLevel   = TSS_SAPI_FIRST_LEVEL,
        .tssVersion = TSS_SAPI_FIRST_VERSION,
    };

    size = Tss2_Sys_GetContextSize (0);
    sapi_ctx = (TSS2_SYS_CONTEXT*)calloc (1, size);
    if (sapi_ctx == NULL) {
        fprintf (stderr,
                 "Failed to allocate 0x%zx bytes for the SAPI context\n",
                 size);
        return NULL;
    }
    rc = Tss2_Sys_Initialize (sapi_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf (stderr, "Failed to initialize SAPI context: 0x%x\n", rc);
        free (sapi_ctx);
        return NULL;
    }
    return sapi_ctx;
}
/*
 * Initialize a SAPI context. Get configuration data from the provided
 * structure.
 */
TSS2_SYS_CONTEXT*
sapi_init_from_options (common_opts_t *options)
{
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_SYS_CONTEXT  *sapi_ctx;

    tcti_ctx = tcti_init_from_options (options);
    if (tcti_ctx == NULL)
        return NULL;
    sapi_ctx = sapi_ctx_init (tcti_ctx);
    if (sapi_ctx == NULL) {
        free (tcti_ctx);
        return NULL;
    }
    return sapi_ctx;
}
/*
 * Initialize a TSS2_TCTI_CONTEXT using whatever TCTI data is in the options
 * structure. This is a mechanism that allows the calling application to be
 * mostly ignorant of which TCTI they're creating / initializing.
 */
TSS2_TCTI_CONTEXT*
tcti_init_from_options (common_opts_t *options)
{
    switch (options->tcti_type) {
#ifdef HAVE_TCTI_DEV
    case DEVICE_TCTI:
        return tcti_device_init (options->device_file);
#endif
#ifdef HAVE_TCTI_SOCK
    case SOCKET_TCTI:
        return tcti_socket_init (options->socket_address,
                                 options->socket_port);
#endif
#ifdef HAVE_TCTI_TABRMD
    case TABRMD_TCTI:
        return tcti_tabrmd_init ();
#endif
    default:
        return NULL;
    }
}
/*
 * Teardown the provided TCTI context. This includes finalizing the
 * context and freeing the data for the context.
 */
void
tcti_teardown (TSS2_TCTI_CONTEXT *tcti_context)
{
    if (tcti_context == NULL)
        return;
    tss2_tcti_finalize (tcti_context);
    free (tcti_context);
}
/*
 * Teardown the provided SAPI context. This includes finalizing the
 * context and freeing the data for the context.
 */
void
sapi_teardown (TSS2_SYS_CONTEXT *sapi_context)
{
    if (sapi_context == NULL)
        return;
    Tss2_Sys_Finalize (sapi_context);
    free (sapi_context);
}
/*
 * Teardown and free the resoruces associted with a SAPI context structure.
 * This includes tearing down the TCTI as well.
 */
void
sapi_teardown_full (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Tss2_Sys_GetTctiContext (sapi_context, &tcti_context);
    if (rc != TSS2_RC_SUCCESS)
        return;
    sapi_teardown (sapi_context);
    tcti_teardown (tcti_context);
}
