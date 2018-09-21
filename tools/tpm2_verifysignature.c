//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_hash.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm2_verifysig_ctx tpm2_verifysig_ctx;
struct tpm2_verifysig_ctx {
    union {
        struct {
            UINT8 digest :1;
            UINT8 halg :1;
            UINT8 msg :1;
            UINT8 sig :1;
            UINT8 ticket :1;
            UINT8 key_context :1;
            UINT8 fmt;
        };
        UINT8 all;
    } flags;
    TPMI_ALG_SIG_SCHEME format;
    TPMI_ALG_HASH halg;
    TPM2B_DIGEST *msgHash;
    TPMT_SIGNATURE signature;
    char *msg_file_path;
    char *sig_file_path;
    char *out_file_path;
    const char *context_arg;
    tpm2_loaded_object key_context_object;
};

tpm2_verifysig_ctx ctx = {
        .format = TPM2_ALG_ERROR,
        .msgHash = NULL,
        .halg = TPM2_ALG_SHA1
};

static bool verify_signature(ESYS_CONTEXT *context) {

    bool ret = true;
    TPMT_TK_VERIFIED *validation;

    TSS2_RC rval = Esys_VerifySignature(context,
                        ctx.key_context_object.tr_handle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        ctx.msgHash, &ctx.signature, &validation);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_VerifySignature, rval);
        ret = false;
        goto out;
    }

    /*
     * NULL Hierarchies don't produce validation data, so let the user know
     * by issuing a warning.
     */
    if (ctx.out_file_path) {
        if (validation->hierarchy == TPM2_RH_NULL) {
            LOG_WARN("The NULL hierarchy doesn't produce a validation ticket,"
                     " not outputting ticket");
            ret = true;
        } else {
            ret = files_save_ticket(validation, ctx.out_file_path);
        }
    }
out:
    free(validation);
    return ret;
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

static bool init(ESYS_CONTEXT *context) {

    /* check flags for mismatches */
    if (ctx.flags.digest && (ctx.flags.msg || ctx.flags.halg)) {
        LOG_ERR(
                "Cannot specify --digest (-D) and ( --msg (-m) or --halg (-g) )");
        return false;
    }

    if (!(ctx.context_arg && ctx.flags.sig)) {
        LOG_ERR(
                "--key-context (-c) and --sig (-s) are required");
        return false;
    }

    TPM2B *msg = NULL;
    bool return_value = false;

    bool tmp = tpm2_util_object_load(context, ctx.context_arg, &ctx.key_context_object);
    if (!tmp) {
        return false;
    }

    if (ctx.flags.msg) {
        msg = message_from_file(ctx.msg_file_path);
        if (!msg) {
            /* message_from_file() logs specific error no need to here */
            return false;
        }
    }

    if (ctx.flags.sig) {

        tpm2_convert_sig_fmt fmt = ctx.flags.fmt ? signature_format_plain : signature_format_tss;
        bool res = tpm2_convert_sig_load(ctx.sig_file_path, fmt, ctx.format, ctx.halg, &ctx.signature);
        if (!res) {
            goto err;
        }
    }

    /* If no digest is specified, compute it */
    if (!ctx.flags.digest) {
        if (!msg) {
            /*
             * This is a redundant check since main() checks this case, but
             * we'll add it here to silence any complainers (such as static
             * analysers).
             */
            LOG_ERR("No digest set and no message file to compute from, cannot compute message hash!");
            goto err;
        }
        bool res = tpm2_hash_compute_data(context, ctx.halg,
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
	case 'c':
	    ctx.context_arg = value;
	    break;
	case 'G': {
		ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
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
        ctx.msgHash = malloc(sizeof(TPM2B_DIGEST));
	    ctx.msgHash->size = sizeof(ctx.msgHash->buffer);
		if (!files_load_bytes_from_path(value, ctx.msgHash->buffer, &ctx.msgHash->size)) {
			LOG_ERR("Could not load digest from file!");
			return false;
		}
		ctx.flags.digest = 1;
	}
		break;
	case 'f': {
		ctx.format = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
		if (ctx.format == TPM2_ALG_ERROR) {
		    LOG_ERR("Unknown signing scheme, got: \"%s\"", value);
		    return false;
		}

		ctx.flags.fmt = 1;
	} break;
	case 's':
		ctx.sig_file_path = value;
		ctx.flags.sig = 1;
		break;
	case 't':
		ctx.out_file_path = value;
		ctx.flags.ticket = 1;
		break;
		/* no default */
	}

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
            { "digest",       required_argument, NULL, 'D' },
            { "halg",         required_argument, NULL, 'G' },
            { "message",      required_argument, NULL, 'm' },
            { "format",      required_argument, NULL,  'f' },
            { "sig",          required_argument, NULL, 's' },
            { "ticket",       required_argument, NULL, 't' },
            { "key-context",  required_argument, NULL, 'c' },
    };


    *opts = tpm2_options_new("G:m:D:f:s:t:c:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

	UNUSED(flags);

    /* initialize and process */
    bool res = init(context);
    if (!res) {
        return 1;
    }

    res = verify_signature(context);
    if (!res) {
        LOG_ERR("Verify signature failed!");
        return 1;
    }

    return 0;
}

void tpm2_tool_onexit(void) {
    if (ctx.msgHash) {
        free(ctx.msgHash);
    }
}
