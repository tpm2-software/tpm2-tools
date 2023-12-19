/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <tss2/tss2_tctildr.h>

#include <sys/types.h>
#include <sys/stat.h>

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
static struct tool_context {
    ESYS_CONTEXT *ectx;
    tpm2_options *tool_opts;
} ctx;

static void main_onexit(void) {

    teardown_full(&ctx.ectx);
    tpm2_options_free(ctx.tool_opts);
}

int main(int argc, char **argv) {

    /* get rid of:
     *   owner execute (1)
     *   group execute (1)
     *   other write + read + execute (7)
     */
    umask(0117);

    char *argv0 = basename(argv[0]);
    bool is_str_tpm2 = (strcmp(argv0, "tpm2") == 0);

    bool is_one_opt_specified = (argc == 2 && is_str_tpm2);

    bool is_opt_str_help = (is_one_opt_specified &&
        ((strcmp(argv[1],"--help") == 0) || (strcmp(argv[1],"-h") == 0) ||
         (strcmp(argv[1],"--help=man") == 0)));

    bool is_no_opts = (is_str_tpm2 && argc == 1);

    if (is_no_opts || is_opt_str_help) {
        char *options[2] = {"tpm2","--help=man"};
        tpm2_handle_options(2, options, 0, 0, 0);
        tool_rc rc = is_no_opts ? tool_rc_option_error : tool_rc_success;
        exit(rc);
    }

    bool is_opt_str_help_no_man = (is_one_opt_specified &&
        (strcmp(argv[1],"--help=no-man") == 0));

    if (is_opt_str_help_no_man) {
        tpm2_tool_output("Specify [ -v | --version ], [-h | --help] or one of "
            "the following tool names:\n");
        for(unsigned i = 0 ; i < tool_count ; i++) {
            fprintf(stderr, "%s\n", tools[i]->name);
        }

        exit(tool_rc_success);
    }

    bool is_opt_str_version = (is_one_opt_specified &&
        ((strcmp(argv[1],"--version") == 0) || (strcmp(argv[1],"-v") == 0)));

    if (is_opt_str_version) {
        tpm2_handle_options(argc, argv, 0, 0, 0);
        exit(tool_rc_success);
    }


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
        exit(tool_rc_general_error);
    }

    atexit(main_onexit);

    tool_rc ret = tool_rc_general_error;
    if (tool->onstart) {
        bool res = tool->onstart(&ctx.tool_opts);
        if (!res) {
            LOG_ERR("retrieving tool options");
            exit(tool_rc_general_error);
        }
    }

    if (tool->onexit) {
        atexit(tool->onexit);
    }

    tpm2_option_flags flags = { .all = 0 };
    TSS2_TCTI_CONTEXT *tcti = NULL;
    tpm2_option_code rc = tpm2_handle_options(argc, argv, ctx.tool_opts, &flags,
            &tcti);
    if (rc != tpm2_option_code_continue) {
        ret = rc == tpm2_option_code_err ?
                tool_rc_general_error : tool_rc_success;
        exit(ret);
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

    if (tcti) {
        ctx.ectx = ctx_init(tcti);
        if (!ctx.ectx) {
            exit(tool_rc_tcti_error);
        }
    }

    if (flags.enable_errata) {
        tpm2_errata_init(ctx.ectx);
    }

    /*
     * Call the specific tool, all tools implement this function instead of
     * 'main'.
     */
    ret = tool->onrun(ctx.ectx, flags);
    if (tool->onstop) {
        tool_rc tmp_rc = tool->onstop(ctx.ectx);
        /* if onrun() passed, the error code should come from onstop() */
        ret = ret == tool_rc_success ? tmp_rc : ret;
    }
    switch (ret) {
    case tool_rc_success:
        /* nothing to do here */
        break;
    case tool_rc_option_error:
        tpm2_print_usage(argv[0], ctx.tool_opts);
        break;
    default:
        LOG_ERR("Unable to run %s", argv[0]);
    }

    exit(ret);
}
