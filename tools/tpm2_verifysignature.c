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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    union {
        struct {
            UINT8 key_handle :1;
            UINT8 digest :1;
            UINT8 halg :1;
            UINT8 msg :1;
            UINT8 raw :1;
            UINT8 sig :1;
            UINT8 ticket :1;
            UINT8 key_context :1;
        };
        UINT8 all;
    } flags;
    TPMI_ALG_HASH halg;
    TPM2B_DIGEST msgHash;
    TPMI_DH_OBJECT keyHandle;
    TPMT_SIGNATURE signature;
    char *msg_file_path;
    char *sig_file_path;
    char *out_file_path;
    char *context_key_file_path;
};

tpm2_verifysig_ctx ctx = {
        .halg = TPM2_ALG_SHA1,
        .msgHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer),
};

static bool verify_signature(TSS2_SYS_CONTEXT *sapi_context) {


    UINT32 rval;
    TPMT_TK_VERIFIED validation;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    UINT16 i;
    for (i = 0; i < ctx.msgHash.size; i++) {
        tpm2_tool_output("%02x ", ctx.msgHash.buffer[i]);
    }
    tpm2_tool_output("\n");

    rval = TSS2_RETRY_EXP(Tss2_Sys_VerifySignature(sapi_context, ctx.keyHandle, NULL,
            &ctx.msgHash, &ctx.signature, &validation, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_VerifySignature, rval);
        return false;
    }

    return files_save_ticket(&validation, ctx.out_file_path);
}

static TPM2B *message_from_file(const char *msg_file_path) {

    unsigned long size;

    bool result = files_get_file_size_path(msg_file_path, &size);
    if (!result) {
        return NULL;
    }

    if (!size) {
        LOG_ERR("The msg file \"%s\" is empty", msg_file_path);
        return NULL;
    }

    TPM2B *msg = (TPM2B *) calloc(1, sizeof(TPM2B) + size);
    if (!msg) {
        LOG_ERR("OOM");
        return NULL;
    }

    UINT16 tmp = msg->size = size;
    if (!files_load_bytes_from_path(msg_file_path, msg->buffer, &tmp)) {
        free(msg);
        return NULL;
    }
    return msg;
}

static bool init(TSS2_SYS_CONTEXT *sapi_context) {

    /* check flags for mismatches */
    if (ctx.flags.digest && (ctx.flags.msg || ctx.flags.halg)) {
        LOG_ERR(
                "Cannot specify --digest (-D) and ( --msg (-m) or --halg (-g) )");
        return false;
    }

    if (!((ctx.flags.key_handle || ctx.flags.key_context) && ctx.flags.sig
            && ctx.flags.ticket)) {
        LOG_ERR(
                "--keyHandle (-k) or --keyContext (-c) and --sig (-s) and --ticket (-t) must be specified");
        return false;
    }

    TPM2B *msg = NULL;
    bool return_value = false;

    if (ctx.flags.msg) {
        msg = message_from_file(ctx.msg_file_path);
        if (!msg) {
            /* message_from_file() logs specific error no need to here */
            return false;
        }
    }

    if (ctx.flags.sig) {
        bool res =  files_load_signature(ctx.sig_file_path, &ctx.signature);
        if (!res) {
            goto err;
        }
    }

    if (ctx.flags.key_context) {
        bool result = files_load_tpm_context_from_path(sapi_context, &ctx.keyHandle,
                ctx.context_key_file_path);
        if (!result) {
            goto err;
        }
    }

    /* If no digest is specified, compute it */
    if (!ctx.flags.digest) {
        if (!ctx.flags.msg) {
            /*
             * This is a redundant check since main() checks this case, but we'll add it here to silence any
             * complainers.
             */
            LOG_ERR("No digest set and no message file to compute from, cannot compute message hash!");
            goto err;
        }
        bool res = tpm2_hash_compute_data(sapi_context, ctx.halg,
                TPM2_RH_NULL, msg->buffer, msg->size, &ctx.msgHash, NULL);
        if (!res) {
            LOG_ERR("Compute message hash failed!");
            goto err;
        }
    }
    return_value = true;

err:
    free(msg);
    return return_value;

}

static bool on_option(char key, char *value) {

	switch (key) {
	case 'k': {
		bool res = tpm2_util_string_to_uint32(value, &ctx.keyHandle);
		if (!res) {
			LOG_ERR("Unable to convert key handle, got: \"%s\"", value);
			return false;
		}
		ctx.flags.key_handle = 1;
	}
		break;
	case 'g': {
		ctx.halg = tpm2_alg_util_from_optarg(value);
		if (ctx.halg == TPM2_ALG_ERROR) {
			LOG_ERR("Unable to convert algorithm, got: \"%s\"", value);
			return false;
		}
		ctx.flags.halg = 1;
	}
		break;
	case 'm': {
		ctx.msg_file_path = value;
		ctx.flags.msg = 1;
	}
		break;
	case 'D': {
	    ctx.msgHash.size = sizeof(ctx.msgHash.buffer);
		if (!files_load_bytes_from_path(value, ctx.msgHash.buffer, &ctx.msgHash.size)) {
			LOG_ERR("Could not load digest from file!");
			return false;
		}
		ctx.flags.digest = 1;
	}
		break;
	case 'r':
		ctx.flags.raw = 1;
		break;
	case 's':
		ctx.sig_file_path = value;
		ctx.flags.sig = 1;
		break;
	case 't':
		ctx.out_file_path = value;

		if (files_does_file_exist(ctx.out_file_path)) {
			return false;
		}
		ctx.flags.ticket = 1;
		break;
	case 'c':
		ctx.context_key_file_path = value;
		ctx.flags.key_context = 1;
		break;
		/* no default */
	}

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
            { "key-handle",  required_argument, NULL, 'k' },
            { "digest",      required_argument, NULL, 'D' },
            { "halg",        required_argument, NULL, 'g' },
            { "message",     required_argument, NULL, 'm' },
            { "raw",         no_argument,       NULL, 'r' },
            { "sig",         required_argument, NULL, 's' },
            { "ticket",      required_argument, NULL, 't' },
            { "key-context", required_argument, NULL, 'c' },
    };


    *opts = tpm2_options_new("k:g:m:D:rs:t:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

	UNUSED(flags);

    /* initialize and process */
    bool res = init(sapi_context);
    if (!res) {
        return 1;
    }

    res = verify_signature(sapi_context);
    if (!res) {
        LOG_ERR("Verify signature failed!");
        return 1;
    }

    return 0;
}
