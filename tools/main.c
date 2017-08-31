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
#include <stdbool.h>

#include "context-util.h"
#include "log.h"
#include "main.h"
#include "options.h"

bool output_enabled = true;

static TSS2_SYS_CONTEXT* sapi_ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    TSS2_ABI_VERSION abi_version = {
            .tssCreator = TSSWG_INTEROP,
            .tssFamily = TSS_SAPI_FIRST_FAMILY,
            .tssLevel = TSS_SAPI_FIRST_LEVEL,
            .tssVersion = TSS_SAPI_FIRST_VERSION,
    };

    size_t size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sapi_ctx = (TSS2_SYS_CONTEXT*) calloc(1, size);
    if (sapi_ctx == NULL) {
        LOG_ERR("Failed to allocate 0x%zx bytes for the SAPI context\n",
                size);
        return NULL;
    }

    TSS2_RC rc = Tss2_Sys_Initialize(sapi_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERR("Failed to initialize SAPI context: 0x%x\n", rc);
        free(sapi_ctx);
        return NULL;
    }

    return sapi_ctx;
}

/*
 * This program is a template for TPM2 tools that use the SAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which TCTI to use for the test.
 */
int main(int argc, char *argv[], char *envp[]) {

    int ret = 1;

    tpm2_options *tool_opts = NULL;
    if (tool_get_options) {
        bool res = tool_get_options(&tool_opts);
        if (!res) {
            LOG_ERR("retrieving tool options");
            return 1;
        }
    }


    tpm2_option_flags flags;
    TSS2_TCTI_CONTEXT *tcti;
    bool res = tpm2_handle_options(argc, argv, envp, tool_opts, &flags, &tcti);
    if (!res) {
        goto free_opts;
    }

    /* figure out the tcti */

    /* TODO SAPI INIT */
    TSS2_SYS_CONTEXT *sapi_context = sapi_ctx_init(tcti);

    /*
     * Call the specific tool, all tools implement this function instead of
     * 'main'.
     */
    ret = tool_execute(sapi_context, flags) ? 1 : 0;
    /*
     * Cleanup contexts & memory allocated for the modified argument vector
     * passed to execute_tool.
     */
    sapi_teardown_full(sapi_context);
free_opts:
    tpm2_options_free(tool_opts);
    exit(ret);
}
