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

typedef struct tpm2_options tpm2_options;

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

static inline void
showVersion (const char *name) {
    #ifdef HAVE_TCTI_TABRMD
      #define TCTI_TABRMD_CONF "tabrmd,"
    #else
      #define TCTI_TABRMD_CONF ""
    #endif

    #ifdef HAVE_TCTI_SOCK
      #define TCTI_SOCK_CONF "socket,"
    #else
      #define TCTI_SOCK_CONF ""
    #endif

    #ifdef HAVE_TCTI_DEV
      #define TCTI_DEV_CONF "device,"
    #else
      #define TCTI_DEV_CONF ""
    #endif

    static const char *tcti_conf = TCTI_TABRMD_CONF TCTI_SOCK_CONF TCTI_DEV_CONF;
    printf("tool=\"%s\" version=\"%s\" tctis=\"%s\"\n", name, VERSION,
            tcti_conf);
}

typedef union tpm2_option_flags tpm2_option_flags;
union tpm2_option_flags {
    struct {
        UINT8 verbose : 1;
        UINT8 quiet   : 1;
        UINT8 unused  : 6;
    };
    UINT8 all;
};

typedef TSS2_TCTI_CONTEXT *(*tcti_init)(char *opts);

typedef bool (*tpm2_option_handler)(char key, char *value);
typedef bool (*tpm2_arg_handler)(int argc, char **argv);

tpm2_options *tpm2_options_new(const char *short_opts, size_t len, struct option *long_opts, tpm2_option_handler on_opt, tpm2_arg_handler on_arg);

tpm2_options *tpm2_options_cat(tpm2_options *a, tpm2_options *b);

void tpm2_options_free(tpm2_options *opts);

bool tpm2_handle_options (int argc, char **argv, char **envp, tpm2_options  *tool_opts, tpm2_option_flags *flags, TSS2_TCTI_CONTEXT **tcti);

#endif /* OPTIONS_H */
