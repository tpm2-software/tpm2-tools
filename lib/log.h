//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
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
