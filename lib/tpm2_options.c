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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <unistd.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

#ifdef HAVE_TCTI_DEV
#include "tpm2_tools_tcti_device.h"
#endif
#ifdef HAVE_TCTI_SOCK
#include "tpm2_tools_tcti_socket.h"
#endif
#ifdef HAVE_TCTI_TABRMD
#include "tpm2_tools_tcti_abrmd.h"
#endif

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

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

#define TPM2TOOLS_ENV_TCTI_NAME      "TPM2TOOLS_TCTI_NAME"

struct tpm2_options {
    struct {
        tpm2_option_handler on_opt;
        tpm2_arg_handler on_arg;
    } callbacks;
    char *short_opts;
    size_t len;
    struct option long_opts[];
};

tpm2_options *tpm2_options_new(const char *short_opts, size_t len,
        const struct option *long_opts, tpm2_option_handler on_opt,
        tpm2_arg_handler on_arg) {

    tpm2_options *opts = calloc(1, sizeof(*opts) + (sizeof(*long_opts) * len));
    if (!opts) {
        LOG_ERR("oom");
        return NULL;
    }

    /*
     * On NULL, just make it a zero length string so we don't have to keep
     * checking it for NULL.
     */
    if (!short_opts) {
        short_opts = "";
    }

    opts->short_opts = strdup(short_opts);
    if (!opts->short_opts) {
        LOG_ERR("oom");
        free(opts);
        return NULL;
    }

    opts->callbacks.on_opt = on_opt;
    opts->callbacks.on_arg = on_arg;
    opts->len = len;
    memcpy(opts->long_opts, long_opts, len * sizeof(*long_opts));

    return opts;
}

bool tpm2_options_cat(tpm2_options **dest, tpm2_options *src) {

    tpm2_options *d = *dest;

    /* move the nested char * pointer first */
    size_t opts_len = strlen(d->short_opts) + strlen(src->short_opts) + 1;
    char *tmp_short = realloc(d->short_opts, opts_len);
    if (!tmp_short) {
        LOG_ERR("oom");
        return false;
    }

    strcat(tmp_short, src->short_opts);

    d->short_opts = tmp_short;

    /* now move the eclosing structure */
    size_t long_opts_len = d->len + src->len;
    /* +1 for a terminating NULL at the end of options array for getopt_long */
    tpm2_options *tmp = realloc(d, sizeof(*d) + ((long_opts_len + 1) * sizeof(d->long_opts[0])));
    if (!tmp) {
        LOG_ERR("oom");
        return false;
    }

    *dest = d = tmp;

    d->callbacks.on_arg = src->callbacks.on_arg;
    d->callbacks.on_opt = src->callbacks.on_opt;

    memcpy(&d->long_opts[d->len], src->long_opts, src->len * sizeof(src->long_opts[0]));

    /* length must be updated post memcpy as we need d->len to be the original offest */
    d->len = long_opts_len;

    /* NULL term for getopt_long */
    memset(&d->long_opts[d->len], 0, sizeof(d->long_opts[0]));

    return true;
}

void tpm2_options_free(tpm2_options *opts) {
    free(opts->short_opts);
    free(opts);
}

#define ADD_TCTI(xname, xinit) { .name = xname, .init = xinit }

/*
 * map a string "nice" name of a tcti to a tcti initialization
 * routine.
 */
struct {
    char       *name;
    tcti_init   init;
} tcti_map_table[] = {
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

static char *tcti_get_opts(char *optstr) {

    char *split = strchr(optstr, ':');
    if (!split) {
        return NULL;
    }

    split[0] = '\0';

    /*
     * make it so downstream consumers don't need to deal with the empty
     * string, ie "". They can just check NULL.
     */
    if (!split[1]) {
        return NULL;
    }

    return &split[1];
}

static void execute_man (char *prog_name, char *envp[]) {

    char *manpage = basename(prog_name);
    char *argv[] = {
        "/man", // ARGv[0] needs to be something.
        manpage,
        NULL
    };
    execvpe ("man", argv, envp);
    LOG_ERR("Could not execute \"man %s\" error: %s", manpage,
            strerror(errno));
}

static void show_version (const char *name) {
    #ifdef HAVE_TCTI_TABRMD
      #define TCTI_TABRMD_CONF "tabrmd,"
    #else
      #define TCTI_TABRMD_CONF ""
    #endif

    #ifdef HAVE_TCTI_SOCK
      #define TCTI_SOCK_CONF "socket,"
    #else
      #define TCTI_SOCK_CONF ""
    #endif

    #ifdef HAVE_TCTI_DEV
      #define TCTI_DEV_CONF "device,"
    #else
      #define TCTI_DEV_CONF ""
    #endif

    static const char *tcti_conf = TCTI_TABRMD_CONF TCTI_SOCK_CONF TCTI_DEV_CONF;
    printf("tool=\"%s\" version=\"%s\" tctis=\"%s\"\n", name, VERSION,
            tcti_conf);
}

tpm2_option_code tpm2_handle_options (int argc, char **argv, char **envp,
        tpm2_options *tool_opts, tpm2_option_flags *flags,
        TSS2_TCTI_CONTEXT **tcti) {

    tpm2_option_code rc = tpm2_option_code_err;
    bool result = false;

    UNUSED(envp);

    /*
     * Handy way to *try* and find all used options:
     * grep -rn case\ \'[a-zA-Z]\' | awk '{print $3}' | sed s/\'//g | sed s/\://g | sort | uniq | less
     */
    struct option long_options [] = {
        { "tcti",           required_argument, NULL, 'T' },
        { "help",           no_argument,       NULL, 'h' },
        { "verbose",        no_argument,       NULL, 'v' },
        { "quiet",          no_argument,       NULL, 'Q' },
        { "version",        no_argument,       NULL, 'V' },
        { "enable-errata", no_argument,        NULL, 'Z' },
    };

    char *tcti_opts = NULL;
    char *tcti_name = TCTI_DEFAULT_STR;
    char *env_str = getenv (TPM2TOOLS_ENV_TCTI_NAME);
    tcti_name = env_str ? env_str : tcti_name;

    /* handle any options */
    tpm2_options *opts = tpm2_options_new("T:hvVQZ",
            ARRAY_LEN(long_options), long_options, NULL, NULL);
    if (!opts) {
        return tpm2_option_code_err;
    }

    /* Get the options from the tool */
    if (tool_opts) {
        result = tpm2_options_cat(&opts, tool_opts);
        if (!result) {
            goto out;
        }
    }

    /* Parse the options, calling the tool callback if unknown */
    int c;
    while ((c = getopt_long (argc, argv, opts->short_opts, opts->long_opts, NULL))
           != -1)
    {
        switch (c) {
        case 'T':
            /* only attempt to get options from tcti option string */
            tcti_name = optarg;
            tcti_opts = tcti_get_opts(optarg);
            break;
        case 'h':
            execute_man(argv[0], envp);
            result = false;
            goto out;
            break;
        case 'V':
            flags->verbose = 1;
            break;
        case 'Q':
            flags->quiet = 1;
            break;
        case 'v':
            show_version(argv[0]);
            rc = tpm2_option_code_stop;
            goto out;
            break;
        case 'Z':
            flags->enable_errata = 1;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            goto out;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            result = false;
            goto out;
        default:
            /* NULL on_opt handler and unkown option specified is an error */
            if (!tool_opts->callbacks.on_opt) {
                LOG_ERR("Unknown options found: %c", c);
                goto out;
            }
            result = tool_opts->callbacks.on_opt(c, optarg);
            if (!result) {
                goto out;
            }
        }
    }

    char **tool_args = &argv[optind];
    int tool_argc = argc - optind;

    /* have args and a handler to process */
    if (tool_argc && tool_opts->callbacks.on_arg) {
        result = tool_opts->callbacks.on_arg(tool_argc, tool_args);
        if (!result) {
            goto out;
        }
    /* have args and no handler, error condition */
    } else if (tool_argc && !tool_opts->callbacks.on_arg) {
        LOG_ERR("Got arguments but the tool takes no arguments");
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

    rc = tpm2_option_code_continue;

out:
    tpm2_options_free(opts);

    return rc;
}
