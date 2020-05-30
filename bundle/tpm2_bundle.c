/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <tss2/tss2_tctildr.h>

#include "log.h"
#include "tpm2_errata.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_tool_output.h"

#include "gen-bundle.h"

typedef struct {
	const char * name;
	bool (*onstart)(tpm2_options **opts);
	tool_rc (*onrun)(ESYS_CONTEXT *ectx, tpm2_option_flags flags);
	tool_rc (*onstop)(ESYS_CONTEXT *ectx);
	void (*onexit)(void);
} tpm2_tool_t;

static const tpm2_tool_t tpm2_tools[] = {
#include "gen-bundle.c"
};

#define SUPPORTED_ABI_VERSION \
{ \
    .tssCreator = 1, \
    .tssFamily = 2, \
    .tssLevel = 1, \
    .tssVersion = 108, \
}

static void esys_teardown(ESYS_CONTEXT **esys_context) {

    if (esys_context == NULL)
        return;
    if (*esys_context == NULL)
        return;
    Esys_Finalize(esys_context);
}

static void teardown_full(ESYS_CONTEXT **esys_context) {

    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    if (!*esys_context) {
        return;
    }

    rc = Esys_GetTcti(*esys_context, &tcti_context);
    if (rc != TPM2_RC_SUCCESS)
        return;
    esys_teardown(esys_context);
    Tss2_TctiLdr_Finalize(&tcti_context);
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
 * This program is a wrapper for all of the TPM2 tools that use the SAPI
 * and pass control to the underlying function.
 *
 * The first argument defines the tool to be run. It is looked up in
 * the table of build in commands, and if found then that tool's onstart,
 * onrun, and onstop functions are called.
 */
int main(int argc, char *argv[])
{
    const char * const tool_name = argv[1];
    if (tool_name == NULL)
    {
        fprintf(stderr, "tpm2: Tool must be specified. Use --help for a list\n");
	return EXIT_FAILURE;
    }

    if (strcmp(tool_name, "--help") == 0
    ||  strcmp(tool_name, "-h") == 0)
    {
	const tpm2_tool_t * tpm2_tool = tpm2_tools;
	while(tpm2_tool->name)
	{
		printf("%s\n", tpm2_tool->name);
		tpm2_tool++;
	}
	return EXIT_SUCCESS;
    }

    // find the matching tool
    const tpm2_tool_t * tpm2_tool = tpm2_tools;
    while(tpm2_tool->name)
    {
	if (strcmp(tpm2_tool->name, tool_name) == 0)
            break;
	tpm2_tool++;
    }
    if (!tpm2_tool->name)
    {
        fprintf(stderr, "tpm2: tool '%s' unknown. Use --help for a list\n", tool_name);
	return EXIT_FAILURE;
    }
    // fixup the argv/argc
    argc--;
    argv++;

    tool_rc ret = tool_rc_general_error;

    tpm2_options *tool_opts = NULL;
    if (tpm2_tool->onstart) {
        bool res = tpm2_tool->onstart(&tool_opts);
        if (!res) {
            LOG_ERR("retrieving tool options");
            return tool_rc_general_error;
        }
    }

    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;
    tpm2_option_code rc = tpm2_handle_options(argc, argv, tool_opts, &flags,
            &tcti);
    if (rc != tpm2_option_code_continue) {
        ret = rc == tpm2_option_code_err ?
                tool_rc_general_error : tool_rc_success;
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
        tpm2_tool_output_disable();
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
    ret = tpm2_tool->onrun(ectx, flags);
    if (tpm2_tool->onstop) {
        tool_rc tmp_rc = tpm2_tool->onstop(ectx);
        /* if onrun() passed, the error code should come from onstop() */
        ret = ret == tool_rc_success ? tmp_rc : ret;
    }
    switch (ret) {
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

    if (tpm2_tool->onexit) {
        tpm2_tool->onexit();
    }

    exit(ret);
}
