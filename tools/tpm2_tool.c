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

static ESYS_CONTEXT *ctx_init(TSS2_TCTI_CONTEXT *tcti_ctx) {

    ESYS_CONTEXT *esys_ctx;

    TSS2_RC rval = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Initialize, rval);
        return NULL;
    }

    return esys_ctx;
}

/*
 * Build a list of the TPM2 tools linked into this executable
 */
#ifndef TPM2_TOOLS_MAX
#define TPM2_TOOLS_MAX 1024
#endif
static const tpm2_tool *tools[TPM2_TOOLS_MAX];
static unsigned tool_count;

void tpm2_tool_register(const tpm2_tool *tool) {

    if (tool_count < TPM2_TOOLS_MAX) {
        tools[tool_count++] = tool;
    } else {
        LOG_ERR("Over tool count");
        abort();
    }
}

static const char *tpm2_tool_name(const char *arg) {

    const char *name = rindex(arg, '/');
    if (name) {
        name++; // skip the '/'
    } else {
        name = arg; // use the full executable name as is
    }

    if (strncmp(name, "tpm2_", 5) == 0) {
        name += 5;
    }

    return name;
}

static const tpm2_tool *tpm2_tool_lookup(int *argc, char ***argv)
{
    // find the executable name in the path
    // and skip "tpm2_" prefix if it is present
    const char *name = tpm2_tool_name((*argv)[0]);

    // if this was invoked as 'tpm2', then try again with the second argument
    if (strcmp(name, "tpm2") == 0) {
        if (--(*argc) == 0) {
            return NULL;
        }
        (*argv)++;
        name = tpm2_tool_name((*argv)[0]);
    }


    // search the tools array for a matching name
    for(unsigned i = 0 ; i < tool_count ; i++)
    {
        const tpm2_tool * const tool = tools[i];
        if (!tool || !tool->name) {
            continue;
        }
        if (strcmp(name, tool->name) == 0) {
            return tool;
        }
    }

    // not found? should print a table of the tools
    return NULL;
}


/*
 * This program is a template for TPM2 tools that use the SAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which TCTI to use for the test.
 */
int main(int argc, char **argv) {

    /* don't buffer stdin/stdout/stderr so pipes work */
    setvbuf (stdin, NULL, _IONBF, 0);
    setvbuf (stdout, NULL, _IONBF, 0);
    setvbuf (stderr, NULL, _IONBF, 0);

    const tpm2_tool * const tool = tpm2_tool_lookup(&argc, &argv);
    if (!tool) {
        LOG_ERR("%s: unknown tool. Available tpm2 commands:", argv[0]);
        for(unsigned i = 0 ; i < tool_count ; i++) {
            fprintf(stderr, "%s\n", tools[i]->name);
        }
        return EXIT_FAILURE;
    }

    tool_rc ret = tool_rc_general_error;
    tpm2_options *tool_opts = NULL;
    if (tool->onstart) {
        bool res = tool->onstart(&tool_opts);
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
    ret = tool->onrun(ectx, flags);
    if (tool->onstop) {
        tool_rc tmp_rc = tool->onstop(ectx);
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

    if (tool->onexit) {
        tool->onexit();
    }

    exit(ret);
}
