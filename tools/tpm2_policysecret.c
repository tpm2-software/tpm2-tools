//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_policysecret_ctx tpm2_policysecret_ctx;
struct tpm2_policysecret_ctx {
    //File path for the session context data
    const char *session_path;
    //File path for storing the policy digest output
    const char *out_policy_dgst_path;
    //Specifying the TPM object handle-id or the file path of context blob
    const char *context_arg;
    tpm2_loaded_object context_object;
    //Auth value of the auth object
    char *auth_str;
    //Auth value length
    UINT16 auth_str_size;
    struct {
        UINT8 c : 1;
        UINT8 p : 1;
    } flags;
    TPMS_AUTH_COMMAND session_data;
};

static tpm2_policysecret_ctx ctx = {
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    .auth_str_size = UINT16_MAX,
    .auth_str = NULL,
};

static bool on_option(char key, char *value) {

    bool result = true;

    switch (key) {
    case 'o':
        ctx.out_policy_dgst_path = value;
        break;
    case 'S':
        ctx.session_path = value;
        break;
    case 'c':
        ctx.context_arg = value;
        ctx.flags.c = 1;
        break;
    }

    return result;
}

bool on_arg (int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Specify a single auth value");
        return false;
    }

    if (!argc) {
        //empty auth
        return true;
    }

    bool result;
    if (!strcmp(argv[0], "-")) {
        //auth data from stdin
        result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,NULL,
                &ctx.auth_str_size, ctx.session_data.hmac.buffer);
        if (!result) {
            return false;
        }
        ctx.session_data.hmac.size = ctx.auth_str_size;
    } else {
        ctx.flags.p = 1;
        ctx.auth_str = argv[0];
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "policy-file", required_argument, NULL, 'o' },
        { "session",     required_argument, NULL, 'S' },
        { "context",     required_argument, NULL, 'c' },
    };

    *opts = tpm2_options_new("o:S:c:", ARRAY_LEN(topts), topts, on_option,
                             on_arg, 0);

    return *opts != NULL;
}

bool is_input_option_args_valid(void) {

    if (!ctx.session_path) {
        LOG_ERR("Must specify -S session file.");
        return false;
    }

    if (!ctx.flags.c) {
        LOG_ERR("Must specify -c handle-id/ context file path.");
        return false;
    }

    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPM2B_DIGEST *policy_digest = NULL;

    bool result = is_input_option_args_valid();
    if (!result) {
        return -1;
    }

    int rc = 1;
    tpm2_session *s = tpm2_session_restore(ectx, ctx.session_path);
    if (!s) {
        return rc;
    }

    tpm2_object_load_rc olrc = tpm2_util_object_load(ectx, ctx.context_arg,
                                &ctx.context_object);
    if (olrc == olrc_error) {
        goto out;
    }
    if (!ctx.context_object.tr_handle) {
        // the handle can be a hierarchy
        ctx.context_object.tr_handle =
            tpm2_tpmi_hierarchy_to_esys_tr(ctx.context_object.handle);
        if (ctx.context_object.tr_handle == ESYS_TR_NONE) {
            result = tpm2_util_sys_handle_to_esys_handle(ectx,
                        ctx.context_object.handle,
                        &ctx.context_object.tr_handle);
            if (!result) {
                goto out;
            }
        }
    }

    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.auth_str,
            &ctx.session_data, NULL);
    }
    if (!result) {
        goto out;
    }

    result = tpm2_policy_build_policysecret(ectx, s,
        ctx.session_data, ctx.context_object.tr_handle);
    if (!result) {
        LOG_ERR("Could not build policysecret ");
        goto out;
    }

    result = tpm2_policy_get_digest(ectx, s, &policy_digest);
    if (!result) {
        LOG_ERR("Could not build tpm policy");
        goto out;
    }

    tpm2_util_hexdump(policy_digest->buffer, policy_digest->size);
    tpm2_tool_output("\n");

    if (ctx.out_policy_dgst_path) {
        result = files_save_bytes_to_file(ctx.out_policy_dgst_path,
                    policy_digest->buffer, policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"",
                    ctx.out_policy_dgst_path);
            goto out;
        }
    }

    result = tpm2_session_save(ectx, s, ctx.session_path);
    if (!result) {
        LOG_ERR("Failed to save policy to file \"%s\"", ctx.session_path);
        goto out;
    }

    rc = 0;

out:
    free(policy_digest);
    tpm2_session_free(&s);
    return rc;
}
