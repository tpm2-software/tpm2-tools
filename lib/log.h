#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdbool.h>
#include <stdio.h>

typedef enum log_level log_level;

/*
 * Prints an error message. The fmt and variadic arguments mirror printf.
 *
 * Use this to log all error conditions.
 */
#define LOG_ERR(fmt, ...) _log(log_level_error, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

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

enum log_level
{
    log_level_error, log_level_warning, log_level_verbose
};

/**
 * Sets the log level so only messages <= to it print.
 * @param level
 *  The logging level to set.
 */
void
log_set_level (log_level level);

void
_log (log_level level, const char *file, unsigned lineno, const char *fmt, ...) __attribute__ ((format (printf, 4, 5)));

#endif /* SRC_LOG_H_ */
