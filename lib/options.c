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
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "options.h"
#include "string-bytes.h"

/*
 * A structure to map a string name to an element in the TCTI_TYPE
 * enumeration.
 */
typedef struct {
    char       *name;
    TCTI_TYPE   type;
} tcti_map_entry_t;
/*
 * A table of tcti_map_entry_t structures. This is how we map a string
 * provided on the command line to the enumeration.
 */
tcti_map_entry_t tcti_map_table[] = {
#ifdef HAVE_TCTI_DEV
    {
        .name = "device",
        .type = DEVICE_TCTI,
    },
#endif
#ifdef HAVE_TCTI_SOCK
    {
        .name = "socket",
        .type = SOCKET_TCTI,
    },
#endif
    {
        .name = "unknown",
        .type = UNKNOWN_TCTI,
    },
};
/*
 * Convert from a string to an element in the TCTI_TYPE enumeration.
 * An unkonwn name / string will map to UNKNOWN_TCTI.
 */
TCTI_TYPE
tcti_type_from_name (char const *tcti_str)
{
    int i;

    if (tcti_str == NULL)
        goto out;
    for (i = 0; i < N_TCTI; ++i)
        if (strcmp (tcti_str, tcti_map_table[i].name) == 0)
            return tcti_map_table[i].type;
out:
    return UNKNOWN_TCTI;
}
/*
 * Convert from an element in the TCTI_TYPE enumeration to a string
 * representation.
 */
char *
tcti_name_from_type (TCTI_TYPE tcti_type)
{
    int i;
    for (i = 0; i < N_TCTI; ++i)
        if (tcti_type == tcti_map_table[i].type)
            return tcti_map_table[i].name;
    return NULL;
}
/*
 * Test a common_opts_t structure to be sure the member data has been
 * populated. We don't do any tests on the data for appropriate formats
 * (like testing socket_address for a valid IP address).
 * return 0 if sanity test passes
 * return 1 if help message was explicitly requested
 * return 2 if sanity test fails
 */
int
sanity_check_common (common_opts_t  *opts)
{
    if (opts->help)
        return 1;
    switch (opts->tcti_type) {
#ifdef HAVE_TCTI_DEV
    case DEVICE_TCTI:
        if (opts->device_file == NULL) {
            fprintf (stderr, "missing --device-file, see --help\n");
            return 2;
        }
        break;
#endif
#ifdef HAVE_TCTI_SOCK
    case SOCKET_TCTI:
        if (opts->socket_address == NULL) {
            fprintf (stderr, "missing --socket-address, see --help\n");
            return 2;
        }
        if (opts->socket_port == 0) {
            fprintf (stderr, "missing --socket-port, see --help\n");
            return 2;
        }
        break;
#endif
    default:
        fprintf (stderr, "invalid TCTI, see --help\n");
        return 2;
    }
    return 0;
}
/*
 * Populate the provided common_opts_t structure with data provided through
 * the environment.
 */
void
get_common_opts_from_env (common_opts_t *common_opts)
{
    char *env_str, *end_ptr;

    if (common_opts == NULL)
        return;
    env_str = getenv (TPM2TOOLS_ENV_TCTI_NAME);
    if (env_str != NULL)
        common_opts->tcti_type = tcti_type_from_name (env_str);
    env_str = getenv (TPM2TOOLS_ENV_DEVICE_FILE);
    if (env_str != NULL)
        common_opts->device_file = env_str;
    env_str = getenv (TPM2TOOLS_ENV_SOCKET_ADDRESS);
    if (env_str != NULL)
        common_opts->socket_address = env_str;
    env_str = getenv (TPM2TOOLS_ENV_SOCKET_PORT);
    if (env_str != NULL)
        common_opts->socket_port = strtol (env_str, &end_ptr, 10);
}
/*
 * Append a string to the parameter argv array. We realloc this array adding
 * a new char* to point to the appended entry. The argc parameter is updated
 * to account for the new element in the array. We return the address of the
 * newly reallocated array. If the realloc fails we return NULL.
 */
char**
append_arg_to_vector (int*  argc,
                      char* argv[],
                      char* arg_string)
{
    char **new_argv;

    ++(*argc);
    new_argv = realloc (argv, sizeof (char*) * (*argc));
    if (new_argv != NULL)
        new_argv[*argc - 1] = arg_string;
    else
        fprintf (stderr,
                 "Failed to realloc new_argv to append string %s: %s\n",
                 arg_string,
                 strerror (errno));

    return new_argv;
}

/*
 * Get data from the environment and the caller (by way of the argument
 * vector) to populate the provided common_opts_t structure. The data we get
 * from the command line / argument vector takes presedence so we fill in the
 * structure with data from the environment first, then from argv. Anything
 * retrieved from the environment will just be over written with whatever we
 * get from argv.
 * All options from argv that aren't from the common option set are ignored
 * and copied to a newly allocated vector. These are assumed to be options
 * specific to the tool. This new augmented argument vector and count are
 * returned to the caller through the argc_param and argv_param. The vector
 * must be freed by the caller.
 */
int
get_common_opts (int                    *argc_param,
                 char                   **argv_param[],
                 common_opts_t          *common_opts)
{
    int argc = *argc_param;
    char **argv = *argv_param;

    int c = 0, option_index = 0;
    char *arg_str = "-T:d:R:p:hvV";
    struct option long_options [] = {
        {
            .name    = "tcti",
            .has_arg = required_argument,
            .flag    = NULL,
            .val     = 'T',
        },
#ifdef HAVET_TCTI_DEV
        {
            .name    = "device-file",
            .has_arg = required_argument,
            .flag    = NULL,
            .val     = 'd',
        },
#endif
#ifdef HAVE_TCTI_SOCK
        {
            .name    = "socket-address",
            .has_arg = required_argument,
            .flag    = NULL,
            .val     = 'R',
        },
        {
            .name    = "socket-port",
            .has_arg = required_argument,
            .flag    = NULL,
            .val     = 'p',
        },
#endif
        {
            .name    = "help",
            .has_arg = no_argument,
            .flag    = &common_opts->help,
            .val     = true,
        },
        {
            .name    = "verbose",
            .has_arg = no_argument,
            .flag    = NULL,
            .val     = 'V',
        },
        {
            .name    = "version",
            .has_arg = no_argument,
            .flag    = NULL,
            .val     = 'v',
        },
        { NULL },
    };
    /*
     * Start by populating the provided common_opts_t structure with data
     * provided in the environment. Whatever we get here will be overriden
     * by stuff from argv.
     */
    get_common_opts_from_env (common_opts);
    /*
     * Keep getopt_long quiet when we see options that aren't in the 'common'
     * category. Reset option processing.
     */
    char **new_argv = { NULL, };
    int new_argc = 1;
    extern int opterr, optind;

    opterr = 0;
    optind = 1;
    new_argv = calloc (1, sizeof (char*));
    if (new_argv == NULL) {
        fprintf (stderr, "Failed to allocate memory for tool argument "
                 "vector: %s\n", strerror (errno));
        return 2;
    }
    new_argv[0] = argv[0];
    while ((c = getopt_long (argc, argv, arg_str, long_options, &option_index))
           != -1)
    {
        switch (c) {
        case 1: /* positional arguments */
            new_argv = append_arg_to_vector (&new_argc, new_argv, optarg);
            if (new_argv == NULL)
                return 2;
            break;
        case 'T':
            common_opts->tcti_type = tcti_type_from_name (optarg);
            break;
#ifdef HAVE_TCTI_DEV
        case 'd':
            common_opts->device_file = optarg;
            break;
#endif
#ifdef HAVE_TCTI_SOCK
        case 'R':
            common_opts->socket_address = optarg;
            break;
        case 'p': {
            bool res = string_bytes_get_uint16(optarg, &common_opts->socket_port);
            if (!res) {
                LOG_ERR("Could not convert port to a 16 bit unsigned number, "
                        "got: %s", optarg);
                return 2;
            }
        }   break;
#endif
        case 'h':
            common_opts->help = true;
            break;
        case 'V':
            common_opts->verbose = true;
            break;
        case 'v':
            common_opts->version = true;
            break;
        case '?':
            new_argv = append_arg_to_vector (&new_argc, new_argv, argv[optind - 1]);
            if (new_argv == NULL)
                return 2;
            break;
        }
    }
    /* return the new argument vector info to the caller */
    *argc_param = new_argc;
    *argv_param = new_argv;

    return 0;
}
/*
 * Dump the contents of the common_opts_t structure to stdout.
 */
void
dump_common_opts (common_opts_t *opts)
{
    printf ("common_opts_t:\n");
    printf ("  tcti_type:        %s\n", tcti_name_from_type (opts->tcti_type));
#ifdef HAVE_TCTI_DEV
    printf ("  device_file_name: %s\n", opts->device_file);
#endif
#ifdef HAVE_TCTI_SOCK
    printf ("  address:          %s\n", opts->socket_address);
    printf ("  port:             %d\n", opts->socket_port);
#endif
    printf ("  help:             %s\n", opts->help    ? "true" : "false");
    printf ("  verbose:          %s\n", opts->verbose ? "true" : "false");
    printf ("  version:          %s\n", opts->version ? "true" : "false");
}
/*
 * Execute man page for the appropriate command.
 */
void
execute_man (char *prog_name,
             char *envp[])
{
        char *argv[] = {
                "/man", // ARGv[0] needs to be something.
                basename(prog_name),
                NULL
        };

        printf("%s\n", basename(prog_name));

        execvpe ("man", argv, envp);
}
