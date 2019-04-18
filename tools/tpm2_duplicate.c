//**********************************************************************;
// Copyright (c) 2017-2018, Intel Corporation
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

//**********************************************************************;
// Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
// Licensed under the Apache License 2.0 (the "License"). You may not use
// this file except in compliance with the License. You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0)
//
// See Victor Shoup, "OAEP reconsidered," Nov. 2000, <URL:
// http://www.shoup.net/papers/oaep.ps.Z> for problems with the security
// proof for the original OAEP scheme, which EME-OAEP is based on. A new
// proof can be found in E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern,
// "RSA-OEAP is Still Alive!", Dec. 2000, <URL:http://eprint.iacr.org/2000/061/>.
// The new proof has stronger requirements for the underlying permutation:
// "partial-one-wayness" instead of one-wayness. For the RSA function, this
// is an equivalent notion.
//**********************************************************************;
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "log.h"
#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

typedef struct tpm_duplicate_ctx tpm_duplicate_ctx;
struct tpm_duplicate_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    char *duplicate_key_public_file;
    char *duplicate_key_private_file;
    
    TPMI_ALG_PUBLIC key_type;
    char *sym_key_in;
    char *sym_key_out;

    char *enc_seed_out;

    const char *new_parent_object_arg;
    tpm2_loaded_object new_parent_object_context;

    char *object_auth_str;
    const char *object_arg;
    tpm2_loaded_object object_context;

    struct {
        UINT16 c : 1;
        UINT16 C : 1;
        UINT16 G : 1;
        UINT16 k : 1;
        UINT16 K : 1;
        UINT16 p : 1;
        UINT16 r : 1;
        UINT16 S : 1;
    } flags;

};

static tpm_duplicate_ctx ctx = {
    .key_type = TPM2_ALG_ERROR,
    .sym_key_in = NULL,
    .sym_key_out = NULL,
    .auth.session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
};

static bool do_duplicate(ESYS_CONTEXT *ectx,
        TPM2B_DATA *in_key,
        TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_DATA **out_key,
        TPM2B_PRIVATE **duplicate,
        TPM2B_ENCRYPTED_SECRET **encrypted_seed) {

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, 
                            ctx.object_context.tr_handle,
                            &ctx.auth.session_data, ctx.auth.session);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Failed to get shandle");
        tpm2_session_free(&ctx.auth.session);
        return false;
    }

    TSS2_RC rval = Esys_Duplicate(ectx, 
                        ctx.object_context.tr_handle, ctx.new_parent_object_context.tr_handle,
                        shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                        in_key, sym_alg, out_key, duplicate, encrypted_seed);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Duplicate, rval);
        tpm2_session_free(&ctx.auth.session);
        return false;
    }

    return true;
}



static bool on_option(char key, char *value) {

    switch(key) {
    case 'p':
        ctx.object_auth_str = value;
        ctx.flags.p = 1;
        break;
    case 'G':
        ctx.key_type = tpm2_alg_util_from_optarg(value, 
                tpm2_alg_util_flags_symmetric
                |tpm2_alg_util_flags_misc);
        if (ctx.key_type != TPM2_ALG_ERROR) {
            ctx.flags.G = 1;
        }
        break;
    case 'k':
        ctx.sym_key_in = value;
        ctx.flags.k = 1;
        break;
    case 'K':
        ctx.sym_key_out = value;
        ctx.flags.K = 1;
        break;
    case 'C':
        ctx.new_parent_object_arg = value;
        ctx.flags.C = 1;
        break;
    case 'c':
        ctx.object_arg = value;
        ctx.flags.c = 1;
        break;
    case 'r':
        ctx.duplicate_key_private_file = value;
        ctx.flags.r = 1;
        break;
    case 'S':
        ctx.enc_seed_out = value;
        ctx.flags.S = 1;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth-key",              required_argument, NULL, 'p'},
      { "inner-wrapper-alg",     required_argument, NULL, 'G'},
      { "duplicate-key-private", required_argument, NULL, 'r'},
      { "input-key-file",        required_argument, NULL, 'k'},
      { "output-key-file",       required_argument, NULL, 'K'},
      { "output-enc-seed-file",  required_argument, NULL, 'S'},
      { "parent-key",            required_argument, NULL, 'C'},
      { "context",               required_argument, NULL, 'c'},
    };

    *opts = tpm2_options_new("p:G:k:C:K:S:r:c:", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

/**
 * Check all options and report as many errors as possible via LOG_ERR.
 * @return
 *  true on success, false on failure.
 */
static bool check_options(void) {

    bool result = true;

    /* Check for NULL alg & (keyin | keyout) */
    if (ctx.flags.G == 0) {
        LOG_ERR("Expected key type to be specified via \"-G\","
                " missing option.");
        result = false;
    }

    if (ctx.key_type != TPM2_ALG_NULL) {
        if((ctx.flags.k == 0) && (ctx.flags.K == 0)) {
            LOG_ERR("Expected in or out encryption key file \"-k/K\","
                    " missing option.");
            result = false;
        }
        if (ctx.flags.k && ctx.flags.K) {
            LOG_ERR("Expected either in or out encryption key file \"-k/K\","
                    " conflicting options.");
            result = false;
        }
    }
    else
    {
        if (ctx.flags.k || ctx.flags.K) {
            LOG_ERR("Expected neither in nor out encryption key file \"-k/K\","
                    " conflicting options.");
            result = false;
        }
    }

    if (ctx.flags.C == 0) {
        LOG_ERR("Expected new parent object to be specified via \"-C\","
                " missing option.");
        result = false;
    }

    if (ctx.flags.c == 0) {
        LOG_ERR("Expected object to be specified via \"-c\","
                " missing option.");
        result = false;
    }

    if (ctx.flags.S == 0) {
        LOG_ERR("Expected encrypted seed out filename to be specified via \"-S\","
                " missing option.");
        result = false;
    }

    if (ctx.flags.r == 0) {
        LOG_ERR("Expected private key out filename to be specified via \"-r\","
                " missing option.");
        result = false;
    }

    return result;
}

static bool load_object(ESYS_CONTEXT *ectx, const char *arg, tpm2_loaded_object * obj)
{
    bool result = true;
    tpm2_object_load_rc rc = tpm2_util_object_load(ectx, arg, obj);

    if (rc != olrc_error) {
        if (!obj->tr_handle) {
            result = tpm2_util_sys_handle_to_esys_handle(ectx, obj->handle, &obj->tr_handle);
        }
    }
    return result;
}

static bool set_key_algorithm(TPMI_ALG_PUBLIC alg, TPMT_SYM_DEF_OBJECT * obj)
{
    bool result = true;
    switch (alg) {

    case TPM2_ALG_AES :
        obj->algorithm = TPM2_ALG_AES;
        obj->keyBits.aes = 128;
        obj->mode.aes = TPM2_ALG_CFB;
        break;

    case TPM2_ALG_NULL :
        obj->algorithm = TPM2_ALG_NULL;
        break;

    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", alg);
        result = false;
        break;
    }

    return result;
}

static bool load_sym_key(TPM2B_DATA * in_key)
{
    FILE *f;
    unsigned long file_size = 0;
    bool result;

    f = fopen(ctx.sym_key_in, "r");
    if (!f) {
        LOG_ERR("Could not open file \"%s\", error: %s",
                ctx.sym_key_in, strerror(errno));
        return false;
    }
    /*
    * Get the file size and validate that it is the proper AES keysize.
    */
    result = files_get_file_size(f, &file_size, ctx.sym_key_in);
    if (!result) {
        return false;
    }

    if(file_size != 16) {
        LOG_ERR("Invalid AES key size, got %lu bytes, expected 16",
                file_size);
        return false;
    }

    in_key->size = file_size;
    result = files_read_bytes(f, in_key->buffer, in_key->size);
    fclose(f);
    if(!result) {
        return false;
    }
    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;
    TPMT_SYM_DEF_OBJECT sym_alg;
    TPM2B_DATA in_key;
    TPM2B_DATA* out_key;
    TPM2B_PRIVATE* duplicate;
    TPM2B_ENCRYPTED_SECRET* outSymSeed;

    result = check_options();
    if (!result) {
        goto out;
    }

    result = load_object(ectx, ctx.object_arg, &ctx.object_context);
    if(!result) {
        goto out;
    }

    result = load_object(ectx, ctx.new_parent_object_arg, &ctx.new_parent_object_context);
    if(!result) {
        goto out;
    }

    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.object_auth_str,
            &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid authorization, got\"%s\"", ctx.object_auth_str);
            goto out;
        }
    }

    result = set_key_algorithm(ctx.key_type, &sym_alg);
    if(!result) {
        goto out;
    }

    if(ctx.flags.k) {
        result = load_sym_key(&in_key);
        if(!result) {
            goto out;
        }
    }

    out_key = NULL;

    result = do_duplicate(ectx,
        ctx.flags.k ? &in_key : NULL,
        &sym_alg,
        ctx.flags.K ? &out_key : NULL,
        &duplicate,
        &outSymSeed);
    if (!result) {
        goto out;
    }


    result = tpm2_session_save(ectx, ctx.auth.session, NULL);
    if (!result) {
        goto out;
    }

    /* Maybe a false positive from scan-build but we'll check out_key anyway */
    if (ctx.flags.K) {
        if(out_key == NULL) {
            LOG_ERR("No encryption key from TPM ");
            goto out;
        }
        result = files_save_bytes_to_file(ctx.sym_key_out,
                    out_key->buffer, out_key->size);
        free(out_key);
        if (!result) {
            LOG_ERR("Failed to save encryption key out into file \"%s\"",
                    ctx.sym_key_out);
            goto out;
        }
    }

    result = files_save_encrypted_seed(outSymSeed, ctx.enc_seed_out);
    free(outSymSeed);
    if (!result) {
        LOG_ERR("Failed to save encryption seed into file \"%s\"",
                ctx.enc_seed_out);
        goto out;
    }

    result = files_save_private(duplicate, ctx.duplicate_key_private_file);
    free(duplicate);
    if (!result) {
        LOG_ERR("Failed to save private key into file \"%s\"",
                ctx.duplicate_key_private_file);
        goto out;
    }

    rc = 0;

out:
    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
