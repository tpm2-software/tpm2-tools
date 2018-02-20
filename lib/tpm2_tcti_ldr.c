//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_tcti_ldr.h"

static void *handle;
static const TSS2_TCTI_INFO *info;

void tpm2_tcti_ldr_unload(void) {
    if (handle) {
#ifndef DISABLE_DLCLOSE
        dlclose(handle);
#endif
        handle = NULL;
        info = NULL;
    }
}

const TSS2_TCTI_INFO *tpm2_tcti_ldr_getinfo(void) {
    return info;
}

TSS2_TCTI_CONTEXT *tpm2_tcti_ldr_load(const char *path, const char *opts) {

    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    if (handle) {
        LOG_ERR("Attempting to load multiple tcti's simultaneously is not supported!");
        return NULL;
    }

    /*
     * Try what they gave us, if it doesn't load up, try
     * libtcti-xxx.so replacing xxx with what they gave us.
     */
    handle = dlopen (path, RTLD_LAZY);
    if (!handle) {

        char buf[PATH_MAX];
        size_t size = snprintf(buf, sizeof(buf), "libtcti-%s.so", path);
        if (size >= sizeof(buf)) {
            LOG_ERR("Truncated friendly name conversion, got: \"%s\", made: \"%s\"",
                    path, buf);
            return NULL;
        }

        handle = dlopen (buf, RTLD_LAZY);
        if (!handle) {
            LOG_ERR("Could not dlopen library: \"%s\"", buf);
            return NULL;
        }
    }

    TSS2_TCTI_INFO_FUNC infofn = (TSS2_TCTI_INFO_FUNC)dlsym(handle, TSS2_TCTI_INFO_SYMBOL);
    if (!infofn) {
        LOG_ERR("Symbol \"%s\"not found in library: \"%s\"",
                TSS2_TCTI_INFO_SYMBOL, path);
        goto err;
    }

    info = infofn();

    TSS2_TCTI_INIT_FUNC init = info->init;

    size_t size;
    TSS2_RC rc = init(NULL, &size, opts);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("tcti init setup routine failed for library: \"%s\""
                " options: \"%s\"", path, opts);
        goto err;
    }

    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
    if (tcti_ctx == NULL) {
        LOG_ERR("oom");
        goto err;
    }

    rc = init(tcti_ctx, &size, opts);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("tcti init allocation routine failed for library: \"%s\""
                " options: \"%s\"", path, opts);
        goto err;
    }

    return tcti_ctx;

err:
    free(tcti_ctx);
    dlclose(handle);
    return NULL;
}
