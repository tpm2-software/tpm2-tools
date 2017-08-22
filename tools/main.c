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

/*
 * This program is a template for TPM2 tools that use the SAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which TCTI to use for the test.
 */
int
main (int   argc,
      char *argv[],
      char *envp[])
{
    extern int opterr, optind;
    int ret;
    TSS2_SYS_CONTEXT *sapi_context;
    common_opts_t opts = COMMON_OPTS_INITIALIZER;
    /*
     * Get common options and reset getopt global variables. This allows the
     * tools to use getopt as they normally would.
     */
    get_common_opts (&argc, &argv, &opts);
    opterr = 0;
    optind = 1;
    switch (sanity_check_common (&opts)) {
    case 1:
        execute_man (argv[0], envp);
        LOG_ERR ("failed to load manpage, check your environment / PATH");
        exit (1);
    case 2:
        exit (1);
    }

    if (opts.version) {
        showVersion (argv[0]);
        exit (0);
    }
    if (opts.verbose)
        log_set_level(log_level_verbose);

    if (opts.quiet) {
        disable_output();
    }

    sapi_context = sapi_init_from_options (&opts);
    if (sapi_context == NULL)
        exit (1);

    /*
     * Per the notes in the manpage, since we use gnu extensions in optstring,
     * we must set optind = 0 to re-initialize a subsequent getopt_long() call.
     * We do this here, so the tools can be ignorant of this fact,
     */
    optind = 0;

    /*
     * Call the specific tool, all tools implement this function instead of
     * 'main'.
     */
    ret = execute_tool (argc, argv, envp, &opts, sapi_context) ? 1 : 0;
    /*
     * Cleanup contexts & memory allocated for the modified argument vector
     * passed to execute_tool.
     */
    sapi_teardown_full (sapi_context);
    free (argv);
    exit (ret);
}
