/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdbool.h>
#include <stdio.h>

#include <tss2/tss2_sys.h>

#include <tss2/tss2_rc.h>
#include "tpm2_util.h"

typedef enum log_level log_level;
enum log_level {
    log_level_error,
    log_level_warning,
    log_level_verbose
};

void _log (log_level level, const char *file, unsigned lineno, const char *fmt, ...)
    COMPILER_ATTR(format (printf, 4, 5));

/*
 * Prints an error message. The fmt and variadic arguments mirror printf.
 *
 * Use this to log all error conditions.
 */
#define LOG_ERR(fmt, ...) _log(log_level_error, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * Prints an error message for a TSS2_Sys call to the TPM.
 * The format is <function-name>(0x<rc>) - <error string>
 * @param func
 *  The function that caused the error
 * @param rc
 *  The return code to print.
 */
#define LOG_PERR(func, rc) _LOG_PERR(xstr(func), rc)

/**
 * Internal use only.
 *
 * Handles the expanded LOG_PERR call checking argument values
 * and handing them off to LOG_ERR.
 * @param func
 *  The function name.
 * @param rc
 *  The rc to decode.
 */
static inline void _LOG_PERR(const char *func, TSS2_RC rc) {

    LOG_ERR("%s(0x%X) - %s", func, rc, Tss2_RC_Decode(rc));
}

/*
 * Prints an warning message. The fmt and variadic arguments mirror printf.
 *
 * Use this to log a warning. A warning is when something is wrong, but it is not a fatal
 * issue.
 */
#define LOG_WARN(fmt, ...) _log(log_level_warning, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/*
 * Prints an informational message. The fmt and variadic arguments mirror printf.
 *
 * Informational messages are only shown when verboseness is increased. Valid messages
 * would be debugging type messages where additional, extraneous information is printed.
 */
#define LOG_INFO(fmt, ...) _log(log_level_verbose, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * Sets the log level so only messages <= to it print.
 * @param level
 *  The logging level to set.
 */
void log_set_level(log_level level);

#endif /* SRC_LOG_H_ */
