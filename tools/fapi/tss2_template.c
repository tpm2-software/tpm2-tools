/* SPDX-License-Identifier: BSD-3-Clause */

#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <tss2/tss2_rc.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "tools/fapi/tss2_template.h"
#include "lib/config.h"
#include "lib/tpm2_alg_util.h"

#define READ_SIZE 1024

/* needed by tpm2_util and tpm2_option functions */
bool output_enabled = false;

static struct termios old;

/* When the program is interrupted during callbacks,
 * restore the old termios state (with ICANON and ECHO) */
static void signal_termio_restore(__attribute__((unused)) int signumber) {
    tcsetattr (STDIN_FILENO, TCSANOW, &old);
}

/* adapted from lib/tpm2_options.c for tss2 */
static bool execute_man(char *prog_name, bool show_errors) {
    pid_t pid;
    int status;

    if ((pid = fork()) < 0) {
        LOG_ERR("Could not fork process to execute man, error: %s",
                strerror(errno));
        return false;
    }

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

        char *manpage = basename(prog_name);
        execlp("man", "man", manpage, NULL);
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

/* adapted from lib/tpm2_options.c for tss2 */
static tpm2_option_code tss2_handle_options (
    int            argc,
    char         **argv,
    tpm2_options **tool_opts) {
    tpm2_option_code rc = tpm2_option_code_err;
    bool show_help = false, manpager = true, explicit_manpager = false;
    struct option long_options [] = {
       {"help"   , optional_argument, NULL, 'h'},
       {"version", no_argument, NULL, 'v'}
    };
    tpm2_options *opts = tpm2_options_new("h::v",
            ARRAY_LEN(long_options), long_options, NULL, NULL, 0);
    if (!opts) {
        return tpm2_option_code_err;
    }
    /* Get the options from the tool */
    if (!*tool_opts || !(*tool_opts)->callbacks.on_opt) {
        fprintf (stderr, "Unknown option found\n");
        goto out;
    }
    tpm2_option_handler on_opt = (*tool_opts)->callbacks.on_opt;
    tpm2_arg_handler on_arg = (*tool_opts)->callbacks.on_arg;
    if (!tpm2_options_cat (tool_opts, opts))
        goto out;
    (*tool_opts)->callbacks.on_opt = on_opt;
    (*tool_opts)->callbacks.on_arg = on_arg;
    /* Parse the options, calling the tool callback if unknown */
    int c;
    while ((c = getopt_long (argc, argv, (*tool_opts)->short_opts,
        (*tool_opts)->long_opts, NULL)) != -1) {
        switch (c) {
        case 'h':
            show_help = true;
            if (argv[optind]) {
                if (!strcmp(argv[optind], "man")) {
                    manpager = true;
                    explicit_manpager = true;
                    optind++;
                } else if (!strcmp(argv[optind], "no-man")) {
                    manpager = false;
                    optind++;
                } else {
                    show_help=false;
                    fprintf (stderr, "Unknown help argument, got: \"%s\"\n",
                        argv[optind]);
                }
            }
            goto out;
            break;
        case 'v': {
            char *prog_name = strdup (argv[0]);
            if (!prog_name) {
                fprintf (stderr, "Not enough memory\n");
                goto out;
            }

            printf("tool=\"%s\" version=\"%s\"\n", basename (prog_name),
                VERSION);

            free(prog_name);
            }
            rc = tpm2_option_code_stop;
            goto out;
        case '?':
            goto out;
        default:
            if (!(*tool_opts)->callbacks.on_opt(c, optarg))
                goto out;
        }
    }

    char **tool_args = &argv[optind];
    int tool_argc = argc - optind;

    /* have args and no handler, error condition */
    if (tool_argc && !(*tool_opts)->callbacks.on_arg) {
        char *prog_name = strdup (argv[0]);
        if (!prog_name) {
            fprintf (stderr, "Not enough memory\n");
            goto out;
        }
        fprintf (stderr, "Got arguments but %s takes no arguments\n",
            basename (prog_name));
        free (prog_name);
        goto out;
    } else if (tool_argc && (*tool_opts)->callbacks.on_arg
        && !(*tool_opts)->callbacks.on_arg(tool_argc, tool_args)) {
        goto out;
    }
    rc = tpm2_option_code_continue;
out:
    /*
     * If help output is selected via -h or indicated by an error that help
     * output is desirable, show it.
     *
     * However, 3 conditions are possible:
     * 1. Try manpager and success -- done, no need to show short help output.
     * 2. Try manpager and failure -- show short help output.
     * 3. Do not use manpager -- show short help output.
     *
     */
    if (show_help) {
        if (!manpager || !execute_man (argv[0], explicit_manpager)) {
            tpm2_print_usage (argv[0], *tool_opts);
        }
        rc = tpm2_option_code_stop;
    }
    tpm2_options_free (opts);

    return rc;
}

char *password = NULL;

TSS2_RC auth_callback(
#ifdef FAPI_3_0
    char const                   *objectPath,
    char const                   *description,
    char const                  **auth,
    void                         *userdata)
{
#else /* FAPI_3_0 */
    __attribute__((unused)) FAPI_CONTEXT *fapi_context,
    char const                   *description,
    char                        **auth,
    void                         *userdata)
{
    const char *objectPath = "object";
#endif /* FAPI_3_0 */

    if (password != NULL) {
        free(password);
        password = NULL;
    }

    struct termios new;
    tcgetattr (STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(ICANON | ECHO);

    if (userdata) {
        printf("%s:", (const char *) userdata);
    } else {
        printf ("Authorize %s \"%s\": ", objectPath, description);
    }
    tcsetattr (STDIN_FILENO, TCSANOW, &new);

    size_t input_size = 0;
    struct sigaction signal_action;
    memset (&signal_action, 0, sizeof signal_action);
    signal_action.sa_handler = signal_termio_restore;
    sigaction (SIGTERM, &signal_action, NULL);
    sigaction (SIGINT, &signal_action, NULL);
    ssize_t getline_ret = getline (&password, &input_size, stdin);
    /* It is intentional, that auth can contain null bytes, and from
     * FAPI’s perspective these terminate the password. */
    tcsetattr (STDIN_FILENO, TCSANOW, &old);
    signal_action.sa_handler = SIG_DFL;
    sigaction (SIGTERM, &signal_action, NULL);
    sigaction (SIGINT, &signal_action, NULL);
    printf ("\n");
    if (getline_ret == -1) {
        fprintf (stderr, "getline() failed: %m\n");
        free (password);
        password = NULL;
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }
    password[getline_ret - 1] = '\0';

#ifdef FAPI_3_0
    *auth = password;
#else /* FAPI_3_0 */
    *auth = strdup(password);
#endif /* FAPI_3_0 */
    return TSS2_RC_SUCCESS;
}

uint8_t *input_signature = NULL;

TSS2_RC sign_callback(
#ifdef FAPI_3_0
    char        const *objectPath,
#else /* FAPI_3_0 */
    __attribute__((unused)) FAPI_CONTEXT *fapi_context,
#endif /* FAPI_3_0 */
    char        const *description,
    char        const *publicKey,
    char        const *publicKeyHint,
    uint32_t    hashAlg,
    uint8_t     const *dataToSign,
    size_t      dataToSignSize,
#ifdef FAPI_3_0
    uint8_t     const **signature,
#else /* FAPI_3_0 */
    uint8_t     **signature,
#endif /* FAPI_3_0 */
    size_t      *signatureSize,
    void        *userData)
{

    if (input_signature != NULL) {
        free(input_signature);
        input_signature = NULL;
    }

    int rc;
    char path[READ_SIZE];
    char publicKeyHintStr[READ_SIZE];

    if (userData) {
        printf("%s:", (const char *) userData);
    } else {
        const char *hashAlgName = tpm2_alg_util_algtostr(hashAlg,
            tpm2_alg_util_flags_hash);
        int cpy_size = 0;
        if (strlen(publicKeyHint) > 0) {
            const char* tmp = "the key corresponding to the key hint \"%s\" and";
            cpy_size = strlen(tmp) - 2 /* remove replaced %s */ +
                strlen(publicKeyHint);
            rc = snprintf(publicKeyHintStr, cpy_size+1 /* add \0 */, tmp,
                publicKeyHint);
            if (rc != cpy_size){
                fprintf (stderr, "Command snprintf failed with %d\n", rc);
                return TSS2_FAPI_RC_GENERAL_FAILURE;
            }
        }
        else {
            const char* tmp = "the key corresponding to the fingerprint \"%s\" and";
            char publicKeyHintTmp[READ_SIZE];
            rc = tpm2_pem_encoded_key_to_fingerprint(publicKey, publicKeyHintTmp);
            if (rc != true){
                fprintf (stderr, "Error getting the fingerprint of the "\
                    "PEM-encoded public key\n");
                return TSS2_FAPI_RC_GENERAL_FAILURE;
            }
            cpy_size = strlen(tmp) - 2 /* remove replaced %s */ +
                strlen(publicKeyHintTmp);
            rc = snprintf(publicKeyHintStr, cpy_size+1 /* add \0 */, tmp,
                publicKeyHintTmp);
            if (rc != cpy_size){
                fprintf (stderr, "Command snprintf failed with %d\n", rc);
                return TSS2_FAPI_RC_GENERAL_FAILURE;
            }
        }

#ifdef FAPI_3_0
        printf("%s: Authorize usage of %s by signing the nonce with %s the hash "\
            "algorithm \"%s\".\n", description, objectPath, publicKeyHintStr,
            hashAlgName);
#else /* FAPI_3_0 */
        printf("%s: Authorize usage of the key by signing the nonce with %s the "\
            "hash algorithm \"%s\".\n", description, publicKeyHintStr,
            hashAlgName);
#endif /* FAPI_3_0 */

    }
    printf("Filename for nonce output: ");
    rc = tpm2_safe_read_from_stdin(READ_SIZE, path);
    if (rc != true){
        fprintf (stderr, "Please enter a valid file path\n");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    rc = open_write_and_close(path, true, dataToSign,
        dataToSignSize);
    if (rc) {
        fprintf (stderr, "Could not write to file: %s\n", path);
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    printf("Filename for signature input: ");
    rc = tpm2_safe_read_from_stdin(READ_SIZE, path);
    if (rc != true){
        fprintf (stderr, "Please enter a valid file path\n");
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    size_t input_signatureSize;
    rc = open_read_and_close (path, (void**)&input_signature,
    &input_signatureSize);
    if (rc) {
        fprintf (stderr, "Could not read from file path: %s\n", path);
        return TSS2_FAPI_RC_GENERAL_FAILURE;
    }

    *signature = input_signature;
    *signatureSize = input_signatureSize;

    return TSS2_RC_SUCCESS;
}

TSS2_RC branch_callback(
#ifdef FAPI_3_0
    char const                     *objectPath,
#else /* FAPI_3_0 */
    __attribute__((unused)) FAPI_CONTEXT *fapi_context,
#endif /* FAPI_3_0 */
    char                    const  *description,
    char                    const **branchNames,
    size_t                          numBranches,
    size_t                         *selectedBranch,
    __attribute__((unused)) void   *userData)
{
#ifdef FAPI_3_0
    printf ("Select a branch for %s \"%s\"\n", objectPath, description);
#else /* FAPI_3_0 */
    printf ("Select a branch for object \"%s\"\n", description);
#endif /* FAPI_3_0 */
    for (size_t i = 0; i < numBranches; i++) {
        printf ("%4zu %s\n", i + 1, branchNames[i]);
    }

    while (1) {
        printf ("Your choice: ");
        if (scanf ("%zu", selectedBranch) != EOF) {
            while (getchar () != '\n'); /* Consume all remaining input */
            if (*selectedBranch > numBranches || *selectedBranch < 1) {
                fprintf (stderr, "The entered integer must be positive and "\
                    "less than %zu.\n", numBranches + 1);
            } else {
                (*selectedBranch)--; /* the user display/choice is always +1 */
                return TSS2_RC_SUCCESS;
            }
        } else {
            fprintf (stderr, "No number received, but EOF.\n");
            return TSS2_FAPI_RC_GENERAL_FAILURE;
        }
    }
}

static FAPI_CONTEXT* ctx_init(char const * uri) {
    FAPI_CONTEXT* ret;
    const unsigned int rval = Fapi_Initialize(&ret, uri);
    if (rval != TSS2_RC_SUCCESS){
        LOG_PERR("Fapi_Initialize", rval);
        return NULL;
    }
    return ret;
}

/*
 * Build a list of the TSS2 tools linked into this executable
 */
#ifndef TSS2_TOOLS_MAX
#define TSS2_TOOLS_MAX 1024
#endif
static const tss2_tool *tools[TSS2_TOOLS_MAX];
static unsigned tool_count;

void tss2_tool_register(const tss2_tool *tool) {

    if (tool_count < TSS2_TOOLS_MAX) {
        tools[tool_count++] = tool;
    } else {
        LOG_ERR("Over tool count");
        abort();
    }
}

static const char *tss2_tool_name(const char *arg) {

    const char *name = rindex(arg, '/');
    if (name) {
        name++; // skip the '/'
    } else {
        name = arg; // use the full executable name as is
    }

    if (strncmp(name, "tss2_", 5) == 0) {
        name += 5;
    }

    return name;
}

static const tss2_tool *tss2_tool_lookup(int *argc, char ***argv)
{
    // find the executable name in the path
    // and skip "tss2_" prefix if it is present
    const char *name = tss2_tool_name((*argv)[0]);

    // if this was invoked as 'tss2', then try again with the second argument
    if (strcmp(name, "tss2") == 0) {
        if (--(*argc) == 0) {
            return NULL;
        }
        (*argv)++;
        name = tss2_tool_name((*argv)[0]);
    }


    // search the tools array for a matching name
    for(unsigned i = 0 ; i < tool_count ; i++)
    {
        const tss2_tool * const tool = tools[i];
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
 * This program is a template for TPM2 tools that use the FAPI. It does
 * nothing more than parsing command line options that allow the caller to
 * specify which FAPI function to call.
 */
int main(int argc, char *argv[]) {

    /* get rid of:
     *   other write + read + execute (7)
     */
    umask(0007);

    const tss2_tool * const tool = tss2_tool_lookup(&argc, &argv);
    if (!tool) {
        LOG_ERR("%s: unknown tool. Available tss2 commands:\n", argv[0]);
        for(unsigned i = 0 ; i < tool_count ; i++) {
            fprintf(stderr, "%s\n", tools[i]->name);
        }
        return EXIT_FAILURE;
    }
    tpm2_options *tool_opts = NULL;
    if (tool->onstart && !tool->onstart (&tool_opts)) {
        fprintf (stderr,"error retrieving tool options\n");
        return 1;
    }
    int ret = 1;

    tpm2_option_code rc = tss2_handle_options (argc, argv, &tool_opts);

    if (rc != tpm2_option_code_continue) {
        ret = rc == tpm2_option_code_err ? 1 : 0;
        goto free_opts;
    }

    FAPI_CONTEXT *fctx = ctx_init (NULL);
    if (!fctx)
        goto free_opts;

    TSS2_RC r = Fapi_SetAuthCB (fctx, auth_callback, NULL);
    if (r != TSS2_RC_SUCCESS) {
        fprintf (stderr, "Fapi_SetAuthCB returned %u\n", r);
        Fapi_Finalize (&fctx);
        goto free_opts;
    }

    r = Fapi_SetSignCB (fctx, sign_callback, NULL);
    if (r != TSS2_RC_SUCCESS) {
        fprintf (stderr, "Fapi_SetSignCB returned %u\n", r);
        Fapi_Finalize (&fctx);
        goto free_opts;
    }

    r = Fapi_SetBranchCB (fctx, branch_callback, NULL);
    if (r != TSS2_RC_SUCCESS) {
        fprintf (stderr, "Fapi_SetBranchCB returned %u\n", r);
        Fapi_Finalize (&fctx);
        goto free_opts;
    }

    /*
     * Call the specific tool, all tools implement this function instead of
     * 'main'.
     * rc 1 = failure
     * rc 0 = success
     * rc -1 = show usage
     */
    ret = tool->onrun(fctx);
    if (ret < 0) {
        tpm2_print_usage(argv[0], tool_opts);
        ret = 1;
    }

    if (tool->onexit) {
        tool->onexit();
    }

    /*
     * Cleanup contexts & memory allocated for the modified argument vector
     * passed to execute_tool.
     */
    Fapi_Finalize (&fctx);
free_opts:
    if (tool_opts)
        tpm2_options_free (tool_opts);
    free (password);
    if (ret == 0){
        free (input_signature);
    }
    exit(ret);
}

int open_write_and_close(const char* path, bool overwrite, const void *output,
    size_t output_len) {

    size_t length = 0;

    if (output_len){
        length = output_len;
    }

    if (!path || !strcmp(path, "-")) {
        if (-1 == write (STDOUT_FILENO, output, length)) {
            fprintf (stderr, "write(2) to stdout failed: %m\n");
            return 1;
        }
        return 0;
    }

    int oflags = O_CREAT | O_WRONLY | O_TRUNC ;
    if (!overwrite) {
        oflags |= O_EXCL;
    }

    int fileno = open (path, oflags, S_IWUSR | S_IRUSR);
    if (fileno == -1) {
        if (errno == EEXIST) {
            fprintf (stderr, "open(2) %s failed: %m\n", path);
        }
        return 1;
    }

    ssize_t bytes_written = write (fileno, output, length);
    if (bytes_written == -1) {
        fprintf (stderr, "write(2) %s failed: %m\n", path);
        close (fileno);
        return 1;
    }
    if (bytes_written - length) {
        fprintf (stderr, "write(2) could not write the whole file, deleting "\
            "%s\n", path);
        unlink (path);
        close (fileno);
        return 1;
    }
    if (close (fileno)) {
        fprintf (stderr, "close(2) %s failed: %m\n", path);
        return 1;
    }
    return 0;
}

int open_read_and_close (const char *path, void **input, size_t *size) {
    if (!path || !strcmp(path, "-")) {
        size_t data_consumed = 0, buffer_size = 1024, data_read;
        *input = malloc (buffer_size + 1);
        if (!*input) {
            fprintf (stderr, "malloc(2) failed: %m\n");
            return 1;
        }
        while ((data_read = read (STDIN_FILENO, *input + data_consumed, 1024))){
            data_consumed += data_read;
            if (data_read < 1024) /* EOF reached */
                break;
            buffer_size += 1024;
            *input = realloc (*input, buffer_size + 1);
            if (!*input) {
                fprintf (stderr, "realloc(3) failed: %m\n");
                return 1;
            }
        }
        if (size)
            *size = data_consumed;
        ((char*)(*input))[data_consumed] = 0;
        return 0;
    }
    int fileno = open (path, O_RDONLY);
    if (fileno == -1) {
        fprintf (stderr, "Opening %s failed: %m\n", path);
        return 1;
    }

    struct stat stat_;
    errno = 0;
    if (fstat (fileno, &stat_)) {
        printf("\nfstat error: [%s]\n",strerror(errno));
        close(fileno);
        return 1;
    }
    if (size)
        *size = stat_.st_size;
    *input = malloc (stat_.st_size + 1);
    if (!*input) {
        fprintf (stderr, "malloc(2) failed: %m\n");
        close (fileno);
        return 1;
    }
    if (-1 == read (fileno, *input, stat_.st_size)) {
        fprintf (stderr, "read(2) %s failed with: %m\n", path);
        free (*input);
        close (fileno);
        return 1;
    }
    ((char*)(*input))[stat_.st_size] = '\0';
    if (close (fileno)) {
        fprintf (stderr, "Error close(2) %s: %m\n", path);
        free (*input);
        return 1;
    }
    return 0;
}

char* ask_for_password() {
#ifdef FAPI_3_0
    const char *pw;
#else /* FAPI_3_0 */
    char *pw;
#endif /* FAPI_3_0 */
    char *ret_pw = NULL;

    if (auth_callback (NULL, NULL, &pw, "New password"))
        goto error;

#ifdef FAPI_3_0
    ret_pw = strdup(pw);
    if (!ret_pw) {
        fprintf (stderr, "OOM\n");
        return NULL;
    }
#else /* FAPI_3_0 */
    ret_pw = pw;
#endif /* FAPI_3_0 */

    if (auth_callback (NULL, NULL, &pw, "Re-enter new password"))
        goto error;

    bool eq = !strcmp (ret_pw, pw);
#ifndef FAPI_3_0
    free(pw);
#endif
    if (!eq) {
        fprintf (stderr, "Passwords do not match.\n");
        goto error;
    }

    return ret_pw;

error:
    if (ret_pw)
        free(ret_pw);

    return NULL;
}

void LOG_PERR(const char *func, TSS2_RC rc) {
    fprintf (stderr, "%s(0x%X) - %s\n", func, rc, Tss2_RC_Decode(rc));
}

void LOG_ERR(const char *format, ...) {
   va_list arg;
   va_start (arg, format);
   vfprintf (stderr, format, arg);
   va_end (arg);
}
