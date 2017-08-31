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
#include "tpm2_util.h"

/*
 * Default TCTI: this is a bit awkward since we allow users to enable /
 * disable TCTIs using ./configure --with/--without magic.
 * As simply put as possible:
 * if the tabrmd TCTI is enabled, it's the default.
 * else if the socket TCTI is enabled it's the default.
 * else if the device TCTI is enabled it's the default.
 * We do this to preserve the current default / expected behavior (use of
 * the socket TCTI).
 */
#ifdef HAVE_TCTI_TABRMD
  #define TCTI_DEFAULT_STR  "abrmd"
#elif HAVE_TCTI_SOCK
  #define TCTI_DEFAULT_STR  "socket"
#elif  HAVE_TCTI_DEV
  #define TCTI_DEFAULT_STR  "device"
#endif

#ifdef HAVE_TCTI_TABRMD
#include "tpm2_tools_tcti_abrmd.h"
#endif
#ifdef HAVE_TCTI_SOCK
#include "tpm2_tools_tcti_socket.h"
#endif
#ifdef HAVE_TCTI_DEV
#include "tpm2_tools_tcti_device.h"
#endif

/* Environment variables usable as alternatives to command line options */
#define TPM2TOOLS_ENV_TCTI_NAME      "TPM2TOOLS_TCTI_NAME"

struct tpm2_options {
    tpm2_option_handler on_opt;
    tpm2_arg_handler on_arg;
    char *short_opts;
    size_t len;
    struct option long_opts[];
};

tpm2_options *tpm2_options_new(const char *short_opts, size_t len, struct option *long_opts, tpm2_option_handler on_opt, tpm2_arg_handler on_arg) {

    tpm2_options *opts = calloc(1, sizeof(*opts) + (sizeof(*long_opts) * len));
    if (!opts) {
        LOG_ERR("oom");
        return NULL;
    }

    opts->short_opts = strdup(short_opts);
    if (!opts) {
        LOG_ERR("oom");
        free(opts);
        return NULL;
    }

    opts->on_opt = on_opt;
    opts->on_arg = on_arg;
    opts->len = len;
    memcpy(opts->long_opts, long_opts, len * sizeof(*long_opts));

    return opts;
}

#define OPTIONS_SIZE(x) (sizeof(*x) + (sizeof(x->long_opts) * x->len))
tpm2_options *tpm2_options_cat(tpm2_options *a, tpm2_options *b) {

    size_t long_opts_len = a->len + b->len;
    /* +1 for a terminating NULL at the end of options array for getopt_long */
    tpm2_options *tmp = calloc(1, sizeof(*a) + 1 + (long_opts_len * sizeof(a->long_opts[0])));
    if (!tmp) {
        LOG_ERR("oom");
        return NULL;
    }

    size_t opts_len = strlen(a->short_opts) + strlen(b->short_opts) + 1;
    tmp->short_opts = calloc(1, opts_len);
    if (!tmp->short_opts) {
        LOG_ERR("oom");
        free(tmp);
        return NULL;
    }

    sprintf(tmp->short_opts, "%s%s", a->short_opts, b->short_opts);

    tmp->len = long_opts_len;

    memcpy(tmp->long_opts, a->long_opts, a->len * sizeof(a->long_opts[0]));
    memcpy(&tmp->long_opts[a->len], b->long_opts, b->len * sizeof(b->long_opts[0]));

    return tmp;
}

void tpm2_options_free(tpm2_options *opts) {
    free(opts->short_opts);
    free(opts);
}

/*
 * A structure to map a string name to an element in the TCTI_TYPE
 * enumeration.
 */
typedef struct {
    char       *name;
    tcti_init   init;
} tcti_map_entry;
/*
 * A table of tcti_map_entry_t structures. This is how we map a string
 * provided on the command line to the enumeration.
 */
#define ADD_TCTI(xname, xinit) { .name = xname, .init = xinit }

tcti_map_entry tcti_map_table[] = {
#ifdef HAVE_TCTI_DEV
    ADD_TCTI("device", tpm2_tools_tcti_device_init),
#endif
#ifdef HAVE_TCTI_SOCK
    ADD_TCTI("socket", tpm2_tools_tcti_socket_init),
#endif
#ifdef HAVE_TCTI_TABRMD
    ADD_TCTI("abrmd", tpm2_tools_tcti_abrmd_init)
#endif
};

bool tpm2_handle_options (int argc, char **argv, char **envp, tpm2_options  *tool_opts, tpm2_option_flags *flags, TSS2_TCTI_CONTEXT **tcti) {

    bool result = false;

    // TODO handle execute man
    UNUSED(envp);

    struct option long_options [] = {
        { "tcti",    required_argument, NULL,   'T' },
        { "help",     no_argument,       NULL,  'h' },
        { "verbose",   no_argument,       NULL, 'v' },
        { "quiet",     no_argument,       NULL, 'Q' },
        { "version",   no_argument,       NULL, 'V' },
    };

    char *tcti_opts = NULL;
    char *tcti_name = TCTI_DEFAULT_STR;
    char *env_str = getenv (TPM2TOOLS_ENV_TCTI_NAME);
    tcti_name = env_str ? env_str : tcti_name;

    /* handle any options */
    tpm2_options *opts = tpm2_options_new("T:hvVQ",
            ARRAY_LEN(long_options), long_options, NULL, NULL);
    if (!opts) {
        return false;
    }

    /* Get the options from the tool */
    if (tool_opts) {
        tpm2_options *tmp = tpm2_options_cat(opts, tool_opts);
        if (!tmp) {
            tpm2_options_free(opts);
            tpm2_options_free(tool_opts);
            return false;
        }
        opts = tmp;
    }

    /* Parse the options, calling the tool callback if unknown */
    int c;
    while ((c = getopt_long (argc, argv, opts->short_opts, opts->long_opts, NULL))
           != -1)
    {
        switch (c) {
        case 'T':
            tcti_name = optarg;
            break;
        case 'h':
            // TODO
            //execute_man();
            break;
        case 'V':
            flags->verbose = 1;
            break;
        case 'Q':
            flags->quiet = 1;
            break;
        case 'v':
            // TODO
            //showversion();
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            goto out;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            result = false;
            goto out;
        default:
            result = tool_opts->on_opt(c, optarg);
            if (!result) {
                goto out;
            }
        }
    }

    char **tool_args = &argv[optind];
    int tool_argc = argc - optind;

    /* have args and a handler to process */
    if (tool_argc && tool_opts->on_arg) {
        result = tool_opts->on_arg(tool_argc, tool_args);
    /* have args and no handler, error condition */
    } else if (tool_argc && !tool_opts->on_arg) {
        result = false;
        goto out;
    }

    size_t i;
    bool found = false;
    for(i=0; i < ARRAY_LEN(tcti_map_table); i++) {

        char *name = tcti_map_table[i].name;
        tcti_init init = tcti_map_table[i].init;
        if (!strcmp(tcti_name, name)) {
            found = true;
            *tcti = init(tcti_opts);
            if (!*tcti) {
                result = false;
                goto out;
            }
        }
    }

    if (!found) {
        LOG_ERR("Unknown tcti, got: \"%s\"", tcti_name);
        result = false;
        goto out;
    }

    result = true;

out:
    tpm2_options_free(opts);

    return result;

}

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
