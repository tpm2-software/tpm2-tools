//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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


#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "password_util.h"
#include "string-bytes.h"

typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_RH_PROVISION auth;
    struct {
        TPMI_DH_OBJECT object;
        TPMI_DH_OBJECT persist;
    } handle;
    TSS2_SYS_CONTEXT *sapi_context;
};

static int evict_control(tpm_evictcontrol_ctx *ctx) {

    TPMS_AUTH_RESPONSE session_data_out;
    TSS2_SYS_CMD_AUTHS sessions_data;
    TSS2_SYS_RSP_AUTHS sessions_data_out;
    TPMS_AUTH_COMMAND *session_data_array[1];
    TPMS_AUTH_RESPONSE *session_ata_out_array[1];

    session_data_array[0] = &ctx->session_data;
    session_ata_out_array[0] = &session_data_out;

    sessions_data_out.rspAuths = &session_ata_out_array[0];
    sessions_data.cmdAuths = &session_data_array[0];

    sessions_data_out.rspAuthsCount = 1;
    sessions_data.cmdAuthsCount = 1;

    TPM_RC rval = Tss2_Sys_EvictControl(ctx->sapi_context, ctx->auth, ctx->handle.object, &sessions_data, ctx->handle.persist,&sessions_data_out);
    if (rval != TPM_RC_SUCCESS) {
        LOG_ERR("EvictControl failed, error code: 0x%x\n", rval);
        return false;
    }
    return true;
}

static bool init(int argc, char *argv[], tpm_evictcontrol_ctx *ctx) {

    const char *optstring = "A:H:S:P:c:X";
    static struct option long_options[] = {
      {"auth",        required_argument, NULL, 'A'},
      {"handle",      required_argument, NULL, 'H'},
      {"persistent",  required_argument, NULL, 'S'},
      {"pwda",        required_argument, NULL, 'P'},
      {"context",     required_argument, NULL, 'c'},
      {"passwdInHex", no_argument,       NULL, 'X'},
      {NULL,          no_argument,       NULL, '\0'}
    };

    struct {
        UINT8 A : 1;
        UINT8 H : 1;
        UINT8 S : 1;
        UINT8 c : 1;
        UINT8 P : 1;
    } flags = { 0 };

    char contextFile[PATH_MAX];

    bool is_hex_passwd = false;

    if (argc == 1) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL))
            != -1) {
        switch (opt) {
        case 'A':
            if (!strcasecmp(optarg, "o")) {
                ctx->auth = TPM_RH_OWNER;
            } else if (!strcasecmp(optarg, "p")) {
                ctx->auth = TPM_RH_PLATFORM;
            } else {
                LOG_ERR("Incorrect auth value, got: \"%s\", expected [o|O|p|P!",
                        optarg);
                return false;
            }
            flags.A = 1;
            break;
        case 'H': {
            bool result = string_bytes_get_uint32(optarg, &ctx->handle.object);
            if (!result) {
                LOG_ERR(
                        "Could not convert object handle to a number, got: \"%s\"",
                        optarg);
                return false;
            }
            flags.H = 1;
        }
            break;
        case 'S': {
            bool result = string_bytes_get_uint32(optarg, &ctx->handle.persist);
            if (!result) {
                LOG_ERR(
                        "Could not convert persistent handle to a number, got: \"%s\"",
                        optarg);
                return false;
            }
            flags.S = 1;
        }
            break;
        case 'P': {
            bool result = password_util_copy_password(optarg, "authenticating",
                    &ctx->session_data.hmac);
            if (result) {
                return false;
            }
            flags.P = 1;
        }
            break;
        case 'c':
            snprintf(contextFile, sizeof(contextFile), "%s", optarg);
            flags.c = 1;
            break;
        case 'X':
            is_hex_passwd = true;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!\n", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c\n", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??\n", opt);
            return false;
        }
    }

    if (!(flags.A && (flags.H || flags.c) && flags.S)) {
        LOG_ERR("Invalid arguments");
        return false;
    }

    bool result = password_util_to_auth(&ctx->session_data.hmac, is_hex_passwd,
            "authenticating", &ctx->session_data.hmac);
    if (!result) {
        return false;
    }

    if (flags.c) {
        result = file_load_tpm_context_from_file(ctx->sapi_context, &ctx->handle.object,
                contextFile);
        if (!result) {
            return false;
        }
    }

    return  true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts and envp are unused, avoid compiler warning */
    (void) opts;
    (void) envp;

    tpm_evictcontrol_ctx ctx = {
            .auth = 0,
            .handle = { 0 },
            .session_data = { 0 },
            .sapi_context = sapi_context
    };

    ctx.session_data.sessionHandle = TPM_RS_PW;

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    /* FIXME required output for testing scripts */
    printf("persistentHandle: 0x%x\n", ctx.handle.persist);

    return evict_control(&ctx) != true;
}
