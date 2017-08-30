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

#include <sapi/tpm20.h>
#include <stdbool.h>
#include "options.h"

extern bool output_enabled;

typedef struct tpm2_options tpm2_options;

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
bool tool_get_options(tpm2_options **opts) __attribute__((weak));

/**
 * This is the main interface for tools, after tcti and sapi initialization
 * are performed.
 * @param sapi_context
 *  The system api context.
 * @param flags
 *  Flags that tools may wish to respect.
 * @return
 *  0 on success.
 */
int tool_execute (TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) __attribute__((weak));

/*
 * Prints output messages if not disabled. Output messages are what tools prints
 * to the standard output during normal execution.
 */
#define TOOL_OUTPUT(fmt, ...)                   \
    do {                                        \
        if (output_enabled) {                   \
            printf(fmt, ##__VA_ARGS__);         \
        }                                       \
    } while (0)

static inline void enable_output(void)
{
    output_enabled = true;
}

static inline void disable_output(void)
{
    output_enabled = false;
}

#endif /* MAIN_H */
