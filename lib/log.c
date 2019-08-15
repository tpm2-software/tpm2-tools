/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

/*
 * Note that the logging library is not thread safe, thus calls on separate
 * threads will yield an interleaved output on stderr.
 */

static log_level current_log_level = log_level_warning;

void log_set_level(log_level value) {
    current_log_level = value;
}

static const char *
get_level_msg(log_level level) {
    const char *value = "UNK";
    switch (level) {
    case log_level_error:
        value = "ERROR";
        break;
    case log_level_warning:
        value = "WARN";
        break;
    case log_level_verbose:
        value = "INFO";
    }
    return value;
}

void _log(log_level level, const char *file, unsigned lineno, const char *fmt,
        ...) {

    /* Skip printing messages outside of the log level */
    if (level > current_log_level)
        return;

    va_list argptr;
    va_start(argptr, fmt);

    /* Verbose output prints file and line on error */
    if (current_log_level >= log_level_verbose) {
        fprintf(stderr, "%s on line: \"%u\" in file: \"%s\": ",
                get_level_msg(level), lineno, file);
    } else {
        fprintf(stderr, "%s: ", get_level_msg(level));
    }

    /* Print the user supplied message */
    vfprintf(stderr, fmt, argptr);

    /* always add a new line so the user doesn't have to */
    fprintf(stderr, "\n");

    va_end(argptr);
}
