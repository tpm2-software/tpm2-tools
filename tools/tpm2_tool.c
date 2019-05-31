/* SPDX-License-Identifier: BSD-3-Clause */

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

    if (!*esys_context) {
        return;
    }

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

/*
 * This program is a template for TPM2 tools that use the SAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which TCTI to use for the test.
 */
int main(int argc, char *argv[]) {

    tool_rc ret = tool_rc_general_error;

    tpm2_options *tool_opts = NULL;
    if (tpm2_tool_onstart) {
        bool res = tpm2_tool_onstart(&tool_opts);
        if (!res) {
            LOG_ERR("retrieving tool options");
            return tool_rc_general_error;
        }
    }

    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;
    tpm2_option_code rc = tpm2_handle_options(argc, argv, tool_opts, &flags, &tcti);
    if (rc != tpm2_option_code_continue) {
        ret = rc == tpm2_option_code_err ? tool_rc_general_error : tool_rc_success;
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

    ESYS_CONTEXT *ectx = NULL;
    if (tcti) {
        ectx = ctx_init(tcti);
        if (!ectx) {
            ret = tool_rc_tcti_error;
            goto free_opts;
        }
    }

    if (flags.enable_errata) {
        tpm2_errata_init(ectx);
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
     */
    ret = tpm2_tool_onrun(ectx, flags);
    if (tpm2_tool_onstop) {
        tool_rc tmp_rc = tpm2_tool_onstop(ectx);
        /* if onrun() passed, the error code should come from onstop() */
        ret = ret == tool_rc_success ? tmp_rc : ret;
    }
    switch(ret) {
        case tool_rc_success:
            /* nothing to do here */
            break;
        case tool_rc_option_error:
            tpm2_print_usage(argv[0], tool_opts);
            break;
        default:
            LOG_ERR("Unable to run %s", argv[0]);
    }

    /*
     * Cleanup contexts & memory allocated for the modified argument vector
     * passed to execute_tool.
     */
    teardown_full(&ectx);

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
