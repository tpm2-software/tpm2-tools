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
#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <getopt.h>

#include <sapi/tpm20.h>

typedef union tpm2_option_flags tpm2_option_flags;
union tpm2_option_flags {
    struct {
        UINT8 verbose : 1;
        UINT8 quiet   : 1;
        UINT8 enable_errata  : 1;
    };
    UINT8 all;
};

/**
 * This function pointer defines the interface for tcti initialization.
 * ALL tool supported TCTIs should implement this interface.
 * @param opts
 *  An option string, that is defined by the tcti, and is passed
 *  via the --tcti= or -T options.
 *
 *  Anything following the : in the --tcti option is provides as opts.
 * @return
 *   NULL on error or an initialized TCTI.
 */
typedef TSS2_TCTI_CONTEXT *(*tcti_init)(char *opts);

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
 * TPM2_OPTIONS_SHOW_USAGE:
 *  Enable printing a short usage summary (I.e. help)
 * TPM2_OPTIONS_NO_SAPI:
 *  Skip SAPI initialization. Removes the "-T" common option.
 */
#define TPM2_OPTIONS_SHOW_USAGE 0x1
#define TPM2_OPTIONS_NO_SAPI 0x2

struct tpm2_options {
    struct {
        tpm2_option_handler on_opt;
        tpm2_arg_handler on_arg;
    } callbacks;
    char *short_opts;
    size_t len;
    UINT32 flags;
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
        tpm2_arg_handler on_arg, UINT32 flags);

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
 * @param envp
 *  The envp from main.
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
tpm2_option_code tpm2_handle_options (int argc, char **argv, char **envp,
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
