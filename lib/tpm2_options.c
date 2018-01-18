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

#include <sys/types.h>
#include <sys/wait.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_tcti_ldr.h"
#include "tpm2_util.h"

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

#define TPM2TOOLS_ENV_TCTI_NAME      "TPM2TOOLS_TCTI_NAME"
#define TPM2TOOLS_ENV_ENABLE_ERRATA  "TPM2TOOLS_ENABLE_ERRATA"

tpm2_options *tpm2_options_new(const char *short_opts, size_t len,
        const struct option *long_opts, tpm2_option_handler on_opt,
        tpm2_arg_handler on_arg, UINT32 flags) {

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
    opts->flags = flags;
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
    d->flags = src->flags;

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

static char *tcti_get_opts(char *optstr) {

    if (!optstr) {
        return NULL;
    }

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

static bool execute_man(char *prog_name) {

    pid_t  pid;
    int status;

    if ((pid = fork()) < 0) {
        LOG_ERR("Could not fork process to execute man, error: %s",
                strerror(errno));
        return false;
    }

    if (pid == 0) {
        char *manpage = basename(prog_name);
        execlp("man", "man", manpage, NULL);
    } else {
        if ((pid = waitpid(pid, &status, 0)) == -1) {
            LOG_ERR("Waiting for child process that executes man failed, error: %s",
                    strerror(errno));
            return false;
        }

        return WEXITSTATUS(status) == 0;
    }

    return true;
}

static void show_version (const char *name) {
#ifndef DISABLE_DLCLOSE
    printf("tool=\"%s\" version=\"%s\" tctis=\"dynamic\"\n", name, VERSION);
#else
    printf("tool=\"%s\" version=\"%s\" tctis=\"dynamic\" dlclose=disabled\n",
            name, VERSION);
#endif
}

void tpm2_print_usage(const char *command, struct tpm2_options *tool_opts) {
    unsigned int i;

    if (!tool_opts || !(tool_opts->flags & TPM2_OPTIONS_SHOW_USAGE)) {
        return;
    }

    printf("usage: %s%s%s\n", command,
           tool_opts->callbacks.on_opt ? " [OPTIONS]" : "",
           tool_opts->callbacks.on_arg ? " ARGUMENTS" : "");

    if (tool_opts->callbacks.on_opt) {
        for (i = 0; i < tool_opts->len; i++) {
            struct option *opt = &tool_opts->long_opts[i];
            printf("[ -%c | --%s%s]", opt->val, opt->name,
                   opt->has_arg ? "=VALUE" : "");
            if ((i + 1) % 4 == 0) {
                printf("\n");
            } else {
                printf(" ");
            }
        }
        if (i % 4 != 0) {
            printf("\n");
        }
    }
}

tpm2_option_code tpm2_handle_options (int argc, char **argv, char **envp,
        tpm2_options *tool_opts, tpm2_option_flags *flags,
        TSS2_TCTI_CONTEXT **tcti) {

    tpm2_option_code rc = tpm2_option_code_err;
    bool result = false;
    bool show_help = false;

    UNUSED(envp);

    /*
     * Handy way to *try* and find all used options:
     * grep -rn case\ \'[a-zA-Z]\' | awk '{print $3}' | sed s/\'//g | sed s/\://g | sort | uniq | less
     */
    struct option long_options [] = {
        { "tcti",          required_argument, NULL, 'T' },
        { "help",          no_argument,       NULL, 'h' },
        { "verbose",       no_argument,       NULL, 'v' },
        { "quiet",         no_argument,       NULL, 'Q' },
        { "version",       no_argument,       NULL, 'V' },
        { "enable-errata", no_argument,       NULL, 'Z' },
    };

    char *tcti_opts = NULL;
    char *tcti_name = "abrmd";
    char *env_str = getenv (TPM2TOOLS_ENV_TCTI_NAME);
    tcti_name = env_str ? env_str : tcti_name;

    /* handle any options */
    const char* common_short_opts = "T:hvVQZ";
    if (tool_opts && (tool_opts->flags & TPM2_OPTIONS_NO_SAPI)) {
        common_short_opts = "hvVQZ";
    }
    tpm2_options *opts = tpm2_options_new(common_short_opts,
            ARRAY_LEN(long_options), long_options, NULL, NULL, true);
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
            break;
        case 'h':
            show_help = true;
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
        case '?':
            goto out;
        default:
            /* NULL on_opt handler and unkown option specified is an error */
            if (!tool_opts || !tool_opts->callbacks.on_opt) {
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

    /* have args and no handler, error condition */
    if (tool_argc && (!tool_opts || !tool_opts->callbacks.on_arg)) {
        LOG_ERR("Got arguments but the tool takes no arguments");
        goto out;
    }
    /* have args and a handler to process */
    else if (tool_argc && tool_opts->callbacks.on_arg) {
        result = tool_opts->callbacks.on_arg(tool_argc, tool_args);
        if (!result) {
            goto out;
        }
	}

    tcti_opts = tcti_get_opts(optarg);

    *tcti = tpm2_tcti_ldr_load(tcti_name, tcti_opts);
    if (!*tcti) {
        LOG_ERR("Unknown tcti, got: \"%s\"", tcti_name);
        goto out;
    }

    if (!flags->enable_errata) {
        flags->enable_errata = !!getenv (TPM2TOOLS_ENV_ENABLE_ERRATA);
    }

    rc = tpm2_option_code_continue;
out:

    if (show_help) {
        bool did_manpager = execute_man(argv[0]);
        if (!did_manpager) {
            tpm2_print_usage(argv[0], tool_opts);
        }

        const TSS2_TCTI_INFO *info = tpm2_tcti_ldr_getinfo();
        if (info) {
            printf("\ntcti-help: %s\n", info->config_help);
        }
        rc = tpm2_option_code_stop;
    }

    tpm2_options_free(opts);

    return rc;
}
