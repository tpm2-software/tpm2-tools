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
#include "options.h"
#include "tpm_table.h"

#ifdef SHELL_TOOLS

#define TOOL_OUTPUT(table, key, value) tpm_table_push(table, key, value)

#define ENTRY_POINT(name) \
    int shell_##name(int argc, char *argv[], char *envp[], common_opts_t *opts, \
        TSS2_SYS_CONTEXT *sapi_context, tpm_table *table __attribute__((unused)))

ENTRY_POINT(activatecredential);
ENTRY_POINT(akparse);
ENTRY_POINT(certify);
ENTRY_POINT(create);
ENTRY_POINT(createpolicy);
ENTRY_POINT(createprimary);
ENTRY_POINT(dictionarylockout);
ENTRY_POINT(dump_capability);
ENTRY_POINT(encryptdecrypt);
ENTRY_POINT(evictcontrol);
ENTRY_POINT(getpubak);
ENTRY_POINT(getpubek);
ENTRY_POINT(getrandom);
ENTRY_POINT(hash);
ENTRY_POINT(hmac);
ENTRY_POINT(listpcrs);
ENTRY_POINT(listpersistent);
ENTRY_POINT(load);
ENTRY_POINT(loadexternal);
ENTRY_POINT(makecredential);
ENTRY_POINT(nvdefine);
ENTRY_POINT(nvlist);
ENTRY_POINT(nvread);
ENTRY_POINT(nvreadlock);
ENTRY_POINT(nvrelease);
ENTRY_POINT(nvwrite);
ENTRY_POINT(quote);
ENTRY_POINT(readpublic);
ENTRY_POINT(rsadecrypt);
ENTRY_POINT(rsaencrypt);
ENTRY_POINT(sign);
ENTRY_POINT(startup);
ENTRY_POINT(takeownership);
ENTRY_POINT(unseal);
ENTRY_POINT(verifysignature);

#else

#define TOOL_OUTPUT(table, key, value) printf("%s:%s\n", key, value)

int
execute_tool (int              argc,
              char             *argv[],
              char             *envp[],
              common_opts_t    *opts,
              TSS2_SYS_CONTEXT *sapi_context,
			  tpm_table *t);

#define ENTRY_POINT(name) \
    int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts, \
        TSS2_SYS_CONTEXT *sapi_context, tpm_table *table __attribute__((unused)))
#endif

#endif /* MAIN_H */
