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
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_tool.h"

/*
 * Both the Microsoft and IBM TPM2 simulators require some specific setup
 * before they can be used by the SAPI. This setup is specific to the
 * simulators and is something that the low-level hardware / firmware does
 * for a discrete TPM.
 * NOTE: In the code that interacts with a TPM this can be a very ugly
 * abstraction leak.
 */

typedef struct startup_opts {
    bool          clear;
    bool          state;
} startup_opts_t;
/*
 * Parse the command line options specific to the 'startup' command.
 * Populate the provided startup_opts_t structure with this data.
 */
void
get_startup_opts (int                 argc,
                  char               *argv[],
                  startup_opts_t     *startup_opts)
{
    int c = 0, option_index = 0;
    char *arg_str = "cs";
    static struct option long_options [] = {
        {
            .name    = "clear",
            .has_arg = no_argument,
            .flag    = NULL,
            .val     = 'c',
        },
        {
            .name    = "state",
            .has_arg = no_argument,
            .flag    = NULL,
            .val     = 's',
        },
        { .name = NULL, },
    };
    while ((c = getopt_long (argc, argv, arg_str, long_options, &option_index))
           != -1)
    {
        switch (c) {
        case 'c':
            startup_opts->clear = true;
            break;
        case 's':
            startup_opts->state = true;
            break;
        }
    }
}

/*
 * Sanity check the options that were passed. This is simply being sure
 * we have either the 'clear' or 'state' flags set but not both.
 */
int
sanity_check_startup_opts (startup_opts_t *startup_opts)
{
    /*
     * Detect when both clear and state are 'true' or 'false'. If this
     * condition fails, then the know that either clear or state are set but
     * not which (but we don't care).
     */
    if (startup_opts->clear == startup_opts->state) {
        LOG_ERR ("Select either '--clear' or '--state'. Try --help.");
        return 1;
    }
    return 0;
}
/*
 * Create a connection to the simulator using the provided parameters:
 * hostname / IP address and port. Then issue the commands necessary to bring
 * the simulator up to a point where it can be used by the SAPI.
 */
int
execute_tool (int               argc,
              char             *argv[],
              char             *envp[],
              common_opts_t    *opts,
              TSS2_SYS_CONTEXT *sapi_context)
{
    (void) opts;
    (void) envp;

    TSS2_RC rc;
    TPM_SU startup_type;
    startup_opts_t startup_opts = {
        .clear       = false,
        .state       = false,
    };

    get_startup_opts (argc, argv, &startup_opts);
    if (sanity_check_startup_opts (&startup_opts))
        return 1;
    /* cheat here a bit and use the 'clear' flag to determine the SU type */
    if (startup_opts.clear)
        startup_type = TPM_SU_CLEAR;
    else
        startup_type = TPM_SU_STATE;

    LOG_INFO ("Sending TPM_Startup command with type: %s",
            startup_opts.clear ? "TPM_SU_CLEAR" : "TPM_SU_STATE");
    rc = Tss2_Sys_Startup (sapi_context, startup_type);
    if (rc != TSS2_RC_SUCCESS && rc != TPM_RC_INITIALIZE) {
        LOG_ERR ("Tss2_Sys_Startup failed: 0x%x",
                 rc);
        return 1;
    }

    LOG_INFO ("Success. TSS2_RC: 0x%x", rc);
    return 0;
}
