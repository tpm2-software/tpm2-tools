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
#ifndef MAIN_H
#define MAIN_H

#ifdef SAPI
#define THE_CONTEXT() TSS2_SYS_CONTEXT
#include <tss2/tss2_sys.h>
#else
#define THE_CONTEXT() ESYS_CONTEXT
#include <tss2/tss2_esys.h>
#endif

#include <stdbool.h>

#include "tpm2_options.h"

extern bool output_enabled;

/**
 * An optional interface for tools to specify what options they support.
 * They are concatenated with main's options and passed to getopt_long.
 * @param opts
 *  The callee can choose to set *opts to a tpm_options pointer allocated
 *  via tpm2_options_new(). Setting *opts to NULL is not an error, and
 *  Indicates that no options are specified by the tool.
 *
 * @return
 *  True on success, false on error.
 */
bool tpm2_tool_onstart(tpm2_options **opts) __attribute__((weak));

/**
 * This is the main interface for tools, after tcti and sapi/esapi initialization
 * are performed.
 * @param context
 *  The system/esapi api context.
 * @param flags
 *  Flags that tools may wish to respect.
 * @return
 *  0 on success
 *  1 on failure
 * -1 to show usage
 */
int tpm2_tool_onrun (THE_CONTEXT() *context, tpm2_option_flags flags) __attribute__((weak));

/**
 * Called when the tool is exiting, useful for cleanup.
 */
void tpm2_tool_onexit(void) __attribute__((weak));

/**
 * prints output to stdout respecting the quiet option.
 * Ie when quiet, don't print.
 * @param fmt
 *  The format specifier, ala printf.
 * @param ...
 *  The varargs, just like printf.
 */
#define tpm2_tool_output(fmt, ...)                   \
    do {                                        \
        if (output_enabled) {                   \
            printf(fmt, ##__VA_ARGS__);         \
        }                                       \
    } while (0)

#endif /* MAIN_H */
