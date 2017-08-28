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

#include <stdint.h>
#include <stdio.h>
#include <sapi/tpm20.h>

/*
 * Default TCTI: this is a bit awkward since we allow users to enable /
 * disable TCTIs using ./configure --with/--without magic.
 * As simply put as possible:
 * if the tabrmd TCTI is enabled, it's the default.
 * else if the socket TCTI is enabled it's the default.
 * else if the device TCTI is enabled it's the default.
 * We do this to preserve the current default / expected behavior (use of
 * the socket TCTI).
 */
#ifdef HAVE_TCTI_TABRMD
  #define TCTI_DEFAULT      TABRMD_TCTI
  #define TCTI_DEFAULT_STR  "tabrmd"
#elif HAVE_TCTI_SOCK
  #define TCTI_DEFAULT      SOCKET_TCTI
  #define TCTI_DEFAULT_STR  "socket"
#elif  HAVE_TCTI_DEV
  #define TCTI_DEFAULT      DEVICE_TCTI
  #define TCTI_DEFAULT_STR  "device"
#endif

/* Defaults for Device TCTI */
#define TCTI_DEVICE_DEFAULT_PATH "/dev/tpm0"

/* Deafults for Socket TCTI connections, port default is for resourcemgr */
#define TCTI_SOCKET_DEFAULT_ADDRESS "127.0.0.1"
#define TCTI_SOCKET_DEFAULT_PORT     2321

/* Environment variables usable as alternatives to command line options */
#define TPM2TOOLS_ENV_TCTI_NAME      "TPM2TOOLS_TCTI_NAME"
#define TPM2TOOLS_ENV_DEVICE_FILE    "TPM2TOOLS_DEVICE_FILE"
#define TPM2TOOLS_ENV_SOCKET_ADDRESS "TPM2TOOLS_SOCKET_ADDRESS"
#define TPM2TOOLS_ENV_SOCKET_PORT    "TPM2TOOLS_SOCKET_PORT"

#define COMMON_OPTS_INITIALIZER { \
    .tcti_type      = TCTI_DEFAULT, \
    .device_file    = TCTI_DEVICE_DEFAULT_PATH, \
    .socket_address = TCTI_SOCKET_DEFAULT_ADDRESS, \
    .socket_port    = TCTI_SOCKET_DEFAULT_PORT, \
    .help           = false, \
    .verbose        = false, \
    .quiet          = false, \
    .version        = false, \
}

typedef enum {
#ifdef HAVE_TCTI_TABRMD
    TABRMD_TCTI,
#endif
#ifdef HAVE_TCTI_SOCK
    SOCKET_TCTI,
#endif
#ifdef HAVE_TCTI_DEV
    DEVICE_TCTI,
#endif
    UNKNOWN_TCTI,
    N_TCTI,
} TCTI_TYPE;

typedef struct {
    TCTI_TYPE tcti_type;
    char     *device_file;
    char     *socket_address;
    uint16_t  socket_port;
    int       help;
    int       verbose;
    int       quiet;
    int       version;
} common_opts_t;

/* functions to get common options from the user and to print helpful stuff */
void        dump_common_opts           (common_opts_t        *opts);
int         get_common_opts            (int                  *argc,
                                        char                 **argv[],
                                        common_opts_t        *common_opts);
int         sanity_check_common        (common_opts_t        *opts);
void        execute_man                (char                 *cmd_name,
                                        char                 *envp[]);

/* inline functions to print messages related to option processing*/
static inline void
showArgError (const char *arg,
              const char *name)
{
    printf("Argument error: %s\n",arg);
    printf("Please type \"%s -h\" get the usage!\n", name);
}

static inline void
showArgMismatch (const char *name)
{
    printf("Argument mismatched!\n");
    printf("Please type \"%s -h\" get the usage!\n", name);
}

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

#endif /* OPTIONS_H */
