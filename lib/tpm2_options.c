/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include <tss2/tss2_tctildr.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "config.h"
#include "log.h"
#include "tpm2_options.h"

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

#define TPM2TOOLS_ENV_TCTI      "TPM2TOOLS_TCTI"
#define TPM2TOOLS_ENV_ENABLE_ERRATA  "TPM2TOOLS_ENABLE_ERRATA"

tpm2_options *tpm2_options_new(const char *short_opts, size_t len,
        const struct option *long_opts, tpm2_option_handler on_opt,
        tpm2_arg_handler on_arg, uint32_t flags) {

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

    /* now move the enclosing structure */
    size_t long_opts_len = d->len + src->len;
    /* +1 for a terminating NULL at the end of options array for getopt_long */
    tpm2_options *tmp = realloc(d,
            sizeof(*d) + ((long_opts_len + 1) * sizeof(d->long_opts[0])));
    if (!tmp) {
        LOG_ERR("oom");
        return false;
    }

    *dest = d = tmp;

    d->callbacks.on_arg = src->callbacks.on_arg;
    d->callbacks.on_opt = src->callbacks.on_opt;
    d->flags = src->flags;

    memcpy(&d->long_opts[d->len], src->long_opts,
            src->len * sizeof(src->long_opts[0]));

    /* length must be updated post memcpy as we need d->len to be the original offset */
    d->len = long_opts_len;

    /* NULL term for getopt_long */
    memset(&d->long_opts[d->len], 0, sizeof(d->long_opts[0]));

    return true;
}

void tpm2_options_free(tpm2_options *opts) {
    if (!opts) {
        return;
    }

    free(opts->short_opts);
    free(opts);
}

static bool execute_man(char *prog_name, bool show_errors) {

    pid_t pid;
    int status;

    if ((pid = fork()) < 0) {
        LOG_ERR("Could not fork process to execute man, error: %s",
                strerror(errno));
        return false;
    }

    #define MAX_TOOL_NAME_LEN 64
    if (pid == 0) {

        if (!show_errors) {
            /* redirect manpager errors to stderr */
            int fd = open("/dev/null", O_WRONLY);
            if (fd < 0) {
                LOG_ERR("Could not open /dev/null");
                return false;
            }
            dup2(fd, 2);
            close(fd);
        }

        const char *manpage = basename(prog_name);
        if (!strcmp(manpage, "tpm2")) {
            /*
             * Handle the case where tpm2 is specified without tool-name or help
             */
            execlp("man", "man", "tpm2", NULL);
        } else if (strncmp(manpage, "tpm2_", strlen("tpm2_"))) {
            /*
             * Handle the case where the tool is specified as tpm2< >tool-name
             */
            char man_tool_name[MAX_TOOL_NAME_LEN] = {'t','p','m','2','_'};
            strncat(man_tool_name, manpage,
                strlen(manpage) < (MAX_TOOL_NAME_LEN - strlen("tpm2_")) ?
                    strlen(manpage) : (MAX_TOOL_NAME_LEN - strlen("tpm2_")));
            execlp("man", "man", man_tool_name, NULL);
        } else {
            /*
             * Handle the case where the tool is specified as tpm2<_>tool-name
             */
            execlp("man", "man", manpage, NULL);
        }
    } else {
        if (waitpid(pid, &status, 0) == -1) {
            LOG_ERR("Waiting for child process that executes man failed, error:"
                    " %s", strerror(errno));
            return false;
        }

        return WEXITSTATUS(status) == 0;
    }

    return true;
}

static void show_version(const char *name) {
    const char *tcti_default = NULL;
    TSS2_TCTI_INFO *info = NULL;

    TSS2_RC rc = Tss2_TctiLdr_GetInfo(NULL, &info);
    if (rc == TSS2_RC_SUCCESS && info != NULL) {
        tcti_default = info->name;
    }

    printf("tool=\"%s\" version=\"%s\" tctis=\"libtss2-tctildr\" tcti-default=%s\n",
            name, VERSION, tcti_default);
    Tss2_TctiLdr_FreeInfo(&info);
}

void tpm2_print_usage(const char *command, struct tpm2_options *tool_opts) {
    unsigned int i;
    bool indent = true;
    char *command_copy;

    if (!tool_opts) {
        return;
    }

    command_copy = strdup(command);
    printf("Usage: %s%s%s\n", basename(command_copy),
           tool_opts->callbacks.on_opt ? " [<options>]" : "",
           tool_opts->callbacks.on_arg ? " <arguments>" : "");
    free(command_copy);

    if (tool_opts->callbacks.on_opt) {
        printf("Where <options> are:\n");
        for (i = 0; i < tool_opts->len; i++) {
            struct option *opt = &tool_opts->long_opts[i];

            if (indent) {
                printf("    ");
                indent = false;
            } else {
                printf(" ");
            }
            if (isalpha(opt->val)) {
                printf("[ -%c | --%s%s]", opt->val, opt->name,
                        opt->has_arg ? "=<value>" : "");
            }
            else {
                printf("[ --%s%s]", opt->name,
                        opt->has_arg ? "=<value>" : "");
            }
            if ((i + 1) % 4 == 0) {
                printf("\n");
                indent = true;
            }
        }
        if (i % 4 != 0) {
            printf("\n");
        }
    }
}

tpm2_option_code tpm2_handle_options(int argc, char **argv,
        tpm2_options *tool_opts, tpm2_option_flags *flags,
        TSS2_TCTI_CONTEXT **tcti) {

    tpm2_option_code rc = tpm2_option_code_err;
    TSS2_RC rc_tcti;
    bool result = false;
    bool show_help = false;
    bool manpager = true;
    bool explicit_manpager = false;

    /*
     * Handy way to *try* and find all used options:
     * grep -rn case\ \'[a-zA-Z]\' | awk '{print $3}' | sed s/\'//g | sed s/\://g | sort | uniq | less
     */
    struct option long_options [] = {
        { "tcti",          required_argument, NULL, 'T' },
        { "help",          optional_argument, NULL, 'h' },
        { "verbose",       no_argument,       NULL, 'V' },
        { "quiet",         no_argument,       NULL, 'Q' },
        { "version",       no_argument,       NULL, 'v' },
        { "enable-errata", no_argument,       NULL, 'Z' },
    };

    const char *tcti_conf_option = NULL;

    /* handle any options */
    const char* common_short_opts = "T:h::vVQZ";
    tpm2_options *opts = tpm2_options_new(common_short_opts,
            ARRAY_LEN(long_options), long_options, NULL, NULL, 0);
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

    optind = 1;

    /* Parse the options, calling the tool callback if unknown */
    int c;
    while ((c = getopt_long(argc, argv, opts->short_opts, opts->long_opts, NULL))
            != -1) {
        switch (c) {
        case 'T':
            if (opts->flags & TPM2_OPTIONS_NO_SAPI) {
                LOG_ERR("%s: tool doesn't support the TCTI option", argv[0]);
                goto out;
            }
            /* only attempt to get options from tcti option string */
            tcti_conf_option = optarg;
            break;
        case 'h':
            show_help = true;
            /*
             * argv[0] = "tool name"
             * argv[1] = "--help=no/man" argv[2] = 0
             */
            if (argv[optind - 1]) {
                if (!strcmp(argv[optind - 1], "--help=no-man") ||
                    !strcmp(argv[optind - 1], "-h=no-man") ||
                    (argv[optind] && !strcmp(argv[optind], "no-man"))) {
                    manpager = false;
                    optind++;
                /*
                 * argv[0] = "tool name"
                 * argv[1] = "--help" argv[2] = "no/man"
                 */
                } else if (!strcmp(argv[optind - 1], "--help=man") ||
                           !strcmp(argv[optind - 1], "-h=man") ||
                           (argv[optind] && !strcmp(argv[optind], "man"))) {
                    manpager = true;
                    explicit_manpager = true;
                    optind++;
                } else {
                    /*
                     * argv[0] = "tool name"
                     * argv[1] = "--help" argv[2] = 0
                     */
                    if (!argv[optind] && argc == 2) {
                        manpager = false;
                    } else {
                        /*
                         * ERROR
                         */
                        show_help = false;
                        LOG_ERR("Unknown help argument, got: \"%s\"", argv[optind]);
                    }
                }
            }
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
        case '?':
            goto out;
        default:
            /* NULL on_opt handler and unknown option specified is an error */
            if (!tool_opts || !tool_opts->callbacks.on_opt) {
                LOG_ERR("Unknown option found: %c", c);
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
        show_help = true;
        goto out;
    }
    /* have args and a handler to process */
    else if (tool_argc && tool_opts->callbacks.on_arg) {
        result = tool_opts->callbacks.on_arg(tool_argc, tool_args);
        if (!result) {
            goto out;
        }
    }

    /* Only init a TCTI if the tool needs it and if the -h/--help option isn't present */
    if (!show_help) {

        /* tool doesn't request a sapi, don't initialize one */
        if (!tool_opts || !(tool_opts->flags & TPM2_OPTIONS_NO_SAPI)) {

            if (tcti_conf_option == NULL)
                tcti_conf_option = tpm2_util_getenv(TPM2TOOLS_ENV_TCTI);
            else if (!strcmp(tcti_conf_option, "none")) {
                if (!tool_opts
                        || !(tool_opts->flags & TPM2_OPTIONS_OPTIONAL_SAPI)) {
                    LOG_ERR("Requested no tcti, but tool requires TCTI.");
                    goto out;
                }
                goto none;
            }
            rc_tcti = Tss2_TctiLdr_Initialize(tcti_conf_option, tcti);
            if (rc_tcti != TSS2_RC_SUCCESS || !*tcti) {
                LOG_ERR("Could not load tcti, got: \"%s\"", tcti_conf_option);
                goto out;
            }
            /*
             * no loader requested ie --tcti=none is an error if tool
             * doesn't indicate an optional SAPI
             */
            if (!flags->enable_errata) {
                flags->enable_errata = !!tpm2_util_getenv(
                        TPM2TOOLS_ENV_ENABLE_ERRATA);
            }
        }
    }
none:
    rc = tpm2_option_code_continue;
out:
    /*
     * If help output is selected via -h or indicated by an error that help output
     * is desirable, show it.
     *
     * However, 3 conditions are possible:
     * 1. Try manpager and success -- done, no need to show short help output.
     * 2. Try manpager and failure -- show short help output.
     * 3. Do not use manpager -- show short help output.
     *
     */
    if (show_help) {
        bool did_manpager = false;
        if (manpager) {
            did_manpager = execute_man(argv[0], explicit_manpager);
        }

        if (!did_manpager) {
            tpm2_print_usage(argv[0], tool_opts);
        }
        if (tcti_conf_option && strcmp(tcti_conf_option, "none")) {
            TSS2_TCTI_INFO *info = NULL;
            rc_tcti = Tss2_TctiLdr_GetInfo(tcti_conf_option, &info);
            if (rc_tcti == TSS2_RC_SUCCESS && info) {
                printf("\ntcti-help(%s): %s\n", info->name, info->config_help);
            }
            Tss2_TctiLdr_FreeInfo(&info);
        }

        rc = tpm2_option_code_stop;
    }

    tpm2_options_free(opts);

    return rc;
}
