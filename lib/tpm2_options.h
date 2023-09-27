/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <getopt.h>
#include <tss2/tss2_sys.h>

#define TPM2TOOLS_ENV_TCTI      "TPM2TOOLS_TCTI"
#define TPM2TOOLS_ENV_AUTOFLUSH "TPM2TOOLS_AUTOFLUSH"

#define TPM2TOOLS_ENV_ENABLE_ERRATA  "TPM2TOOLS_ENABLE_ERRATA"

typedef union tpm2_option_flags tpm2_option_flags;
union tpm2_option_flags {
    struct {
        uint8_t verbose :1;
        uint8_t quiet :1;
        uint8_t enable_errata :1;
        uint8_t tcti_none :1;
    };
    uint8_t all;
};

/**
 * Tools may implement this optional interface if they need
 * to handle options.
 * @param key
 *  The key of the option, ie short option return value from getopt_long().
 * @param value
 *  The getopt_long optarg value.
 * @return
 *  true on success, false on error.
 * @note
 *  LOG_INFO and TOOL_OUTPUT will not work correctly during this callback.
 *  This is called after onstart() finishes, but before
 *  onrun() is invoked.
 *
 */
typedef bool (*tpm2_option_handler)(char key, char *value);

/**
 * Called after option handling to process arguments, if specified.
 * @param argc
 *  The number of args in argv.
 * @param argv
 *  The arguments.
 * @return
 *  true on success, false otherwise.
 * @note
 *  LOG_INFO adn TOOL_OUTPUT will not work correctly during this callback.
 *  This is called after onstart() and tpm2_option_handler() (if specified),
 *  but before onrun() is invoked.
 *
 */
typedef bool (*tpm2_arg_handler)(int argc, char **argv);

/**
 * TPM2_OPTIONS_* flags change default behavior of the argument parser
 *
 * TPM2_OPTIONS_NO_SAPI:
 *  Skip SAPI initialization. Removes the "-T" common option.
 */
#define TPM2_OPTIONS_NO_SAPI       (1 << 0)
#define TPM2_OPTIONS_OPTIONAL_SAPI (1 << 1)
#define TPM2_OPTIONS_FAKE_TCTI     (1 << 3)

struct tpm2_options {
    struct {
        tpm2_option_handler on_opt;
        tpm2_arg_handler on_arg;
    } callbacks;
    char *short_opts;
    size_t len;
    uint32_t flags;
    struct option long_opts[];
};

typedef struct tpm2_options tpm2_options;

/**
 * The onstart() routine expects a return of NULL or a tpm2_options structure.
 * This routine initializes said object.
 * @param short_opts
 *  Any short options you wish to specify to getopt_long.
 * @param len
 *  The length of the long_opts array.
 * @param long_opts
 *  Any long options you wish to specify to getopt_long().
 * @param on_opt
 *  An option handling callback, which may be null if you don't wish
 *  to handle options.
 * @param on_arg
 *  An argument handling callback, which may be null if you don't wish
 *  to handle arguments.
 * @param flags
 *  TPM2_OPTIONS_* bit flags
 * @return
 *  NULL on failure or an initialized tpm2_options object.
 */
tpm2_options *tpm2_options_new(const char *short_opts, size_t len,
        const struct option *long_opts, tpm2_option_handler on_opt,
        tpm2_arg_handler on_arg, uint32_t flags);

/**
 * Concatenates two tpm2_options objects, with src appended on
 * dest. The internal callbacks for tpm2_arg_handler and tpm2_option_handler
 * which were specified during tpm2_options_new() are copied from src to
 * dest, thus overwriting dest. Short and long options are concatenated.
 * @param dest
 *  The tpm2_options object to append to.
 * @param src
 *  The source tpm2_options to append onto dest.
 * @return
 *  true on success, false otherwise.
 */
bool tpm2_options_cat(tpm2_options **dest, tpm2_options *src);

/**
 * Free's a tpm2_options created via tpm2_options_new().
 * @param opts
 *  The tpm2_options object to deallocate.
 */
void tpm2_options_free(tpm2_options *opts);

typedef enum tpm2_option_code tpm2_option_code;
enum tpm2_option_code {
    tpm2_option_code_continue,
    tpm2_option_code_stop,
    tpm2_option_code_err
};

/**
 * Parses the tpm2_tool command line.
 *
 * @param argc
 *  The argc from main.
 * @param argv
 *  The argv from main.
 * @param tool_opts
 *  The tool options gathered during onstart() lifecycle call.
 * @param flags
 *  The tpm2_option_flags to set during parsing.
 * @param tcti
 *  The tcti initialized from the tcti options.
 * @return
 *  A tpm option code indicating if an error, further processing
 *  or an immediate exit is desired.
 * @note
 *  Used by tpm2_tool, and likely should only be used there.
 *
 */
tpm2_option_code tpm2_handle_options(int argc, char **argv,
        tpm2_options *tool_opts, tpm2_option_flags *flags,
        TSS2_TCTI_CONTEXT **tcti);

/**
 * Print usage summary for a given tpm2 tool.
 *
 * @param command
 *  The command to print its usage summary text.
 * @param tool_opts
 *  The tpm2_options array that contains the tool options to print as a summary.
 */
void tpm2_print_usage(const char *command, struct tpm2_options *tool_opts);

#endif /* OPTIONS_H */
