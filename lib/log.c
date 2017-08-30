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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include "log.h"

/*
 * Note that the logging library is not thread safe, thus calls on separate
 * threads will yield an interleaved output on stderr.
 */

static log_level current_log_level = log_level_warning;

void
log_set_level (log_level value)
{
    current_log_level = value;
}

static const char *
get_level_msg (log_level level)
{
    const char *value = "UNK";
    switch (level)
    {
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

void
_log (log_level level, const char *file, unsigned lineno, const char *fmt, ...)
{

    /* Skip printing messages outside of the log level */
    if (level > current_log_level)
        return;

    va_list argptr;
    va_start(argptr, fmt);

    /* Verbose output prints file and line on error */
    if (current_log_level >= log_level_verbose)
        fprintf (stderr, "%s on line: \"%u\" in file: \"%s\": ",
                 get_level_msg (level), lineno, file);
    else
        fprintf (stderr, "%s: ", get_level_msg (level));

    /* Print the user supplied message */
    vfprintf (stderr, fmt, argptr);

    /* always add a new line so the user doesn't have to */
    fprintf (stderr, "\n");

    va_end(argptr);
}
