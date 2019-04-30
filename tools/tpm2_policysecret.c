/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
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
    struct {
        UINT8 c : 1;
    } flags;
};

static tpm2_policysecret_ctx ctx;

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

    ctx.auth_str = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        { "out-policy-file", required_argument, NULL, 'o' },
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

    result = tpm2_util_object_load(ectx, ctx.context_arg,
                                &ctx.context_object);
    if (!result) {
        goto out;
    }

    tpm2_session *pwd_session;
    result = tpm2_auth_util_from_optarg(ectx, ctx.auth_str,
        &pwd_session, false);
    if (!result) {
        goto out;
    }

    result = tpm2_policy_build_policysecret(ectx, s,
        pwd_session, ctx.context_object.tr_handle);
    tpm2_session_free(&pwd_session);
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
