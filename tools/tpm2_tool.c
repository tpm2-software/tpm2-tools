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
#include <stdlib.h>

#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "log.h"
#include "tpm2_tcti_ldr.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_errata.h"

#define SUPPORTED_ABI_VERSION \
{ \
    .tssCreator = 1, \
    .tssFamily = 2, \
    .tssLevel = 1, \
    .tssVersion = 108, \
}

bool output_enabled = true;

static void tcti_teardown (TSS2_TCTI_CONTEXT *tcti_context) {

    Tss2_Tcti_Finalize (tcti_context);
    free (tcti_context);
}

#ifdef SAPI

static void sapi_teardown (TSS2_SYS_CONTEXT *sapi_context) {

    if (sapi_context == NULL)
        return;
    Tss2_Sys_Finalize (sapi_context);
    free (sapi_context);
}

static void teardown_full (TSS2_SYS_CONTEXT *sapi_context) {

    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Tss2_Sys_GetTctiContext (sapi_context, &tcti_context);
    if (rc != TPM2_RC_SUCCESS)
        return;
    sapi_teardown (sapi_context);
    tcti_teardown (tcti_context);
}

static TSS2_SYS_CONTEXT* ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    TSS2_ABI_VERSION abi_version = SUPPORTED_ABI_VERSION;

    size_t size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sapi_ctx = (TSS2_SYS_CONTEXT*) calloc(1, size);
    if (sapi_ctx == NULL) {
        LOG_ERR("Failed to allocate 0x%zx bytes for the SAPI context\n",
                size);
        return NULL;
    }

    TSS2_RC rval = Tss2_Sys_Initialize(sapi_ctx, size, tcti_ctx, &abi_version);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Initialize, rval);
        free(sapi_ctx);
        return NULL;
    }

    return sapi_ctx;
}

#else

static void esys_teardown (ESYS_CONTEXT **esys_context) {

    if (esys_context == NULL)
        return;
    if (*esys_context == NULL)
        return;
    Esys_Finalize (esys_context);
}

static void teardown_full (ESYS_CONTEXT **esys_context) {

    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Esys_GetTcti(*esys_context, &tcti_context);
    if (rc != TPM2_RC_SUCCESS)
        return;
    esys_teardown (esys_context);
    tcti_teardown (tcti_context);
}

static ESYS_CONTEXT* ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    TSS2_ABI_VERSION abi_version = SUPPORTED_ABI_VERSION;
    ESYS_CONTEXT *esys_ctx;

    TSS2_RC rval = Esys_Initialize(&esys_ctx, tcti_ctx, &abi_version);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Initialize, rval);
        return NULL;
    }

    return esys_ctx;
}
#endif


/*
 * This program is a template for TPM2 tools that use the SAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which TCTI to use for the test.
 */
int main(int argc, char *argv[]) {

    int ret = 1;

    tpm2_options *tool_opts = NULL;
    if (tpm2_tool_onstart) {
        bool res = tpm2_tool_onstart(&tool_opts);
        if (!res) {
            LOG_ERR("retrieving tool options");
            return 1;
        }
    }

    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;
    tpm2_option_code rc = tpm2_handle_options(argc, argv, tool_opts, &flags, &tcti);
    if (rc != tpm2_option_code_continue) {
        ret = rc == tpm2_option_code_err ? 1 : 0;
        goto free_opts;
    }

    if (flags.verbose) {
        log_set_level(log_level_verbose);
    }

    /*
     * We don't want a cyclic dependency between tools/options. Resolving those
     * works well on linux/elf based systems, but darwin and windows tend to
     * fall flat on there face. This is why we set quiet mode outside of
     * option and argument life-cycle. Thus TOOL_OUTPUT is only guaranteed
     * to respect quiet from here on out (onrun and onexit).
     */
    if (flags.quiet) {
        output_enabled = false;
    }

    THE_CONTEXT() *context = NULL;
    if (tcti) {
        context = ctx_init(tcti);
        if (!context) {
            goto free_opts;
        }
    }

    if (flags.enable_errata) {
#ifdef SAPI
        tpm2_errata_init_sapi(context);
#else
        tpm2_errata_init(context);
#endif
    }

    /*
     * Load the openssl error strings and algorithms
     * so library routines work as expected.
     */
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();

    /*
     * Call the specific tool, all tools implement this function instead of
     * 'main'.
     * rc 1 = failure
     * rc 0 = success
     * rc -1 = show usage
     */
    ret = tpm2_tool_onrun(context, flags);
    if (ret > 0) {
        LOG_ERR("Unable to run %s", argv[0]);
    } else if (ret < 0) {
        tpm2_print_usage(argv[0], tool_opts);
        ret = 0;
    }

    /*
     * Cleanup contexts & memory allocated for the modified argument vector
     * passed to execute_tool.
     */
#ifdef SAPI
    teardown_full(context);
#else
    teardown_full(&context);
#endif

free_opts:
    if (tool_opts) {
        tpm2_options_free(tool_opts);
    }

    if (tpm2_tool_onexit) {
        tpm2_tool_onexit();
    }

    tpm2_tcti_ldr_unload();

    exit(ret);
}
