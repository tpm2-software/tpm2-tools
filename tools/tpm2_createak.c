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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_sys.h>

#include "tpm2_convert.h"
#include "tpm2_options.h"
#include "tpm2_auth_util.h"
#include "files.h"
#include "log.h"
#include "tpm2_util.h"
#include "tpm2_session.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"
#include "tpm2_capability.h"

typedef struct createak_context createak_context;
struct createak_context {
    struct {
        const char *ctx_arg;
        tpm2_loaded_object ek_ctx;
        struct {
            TPMS_AUTH_COMMAND session_data;
            tpm2_session *session;
        } auth2;
    } ek;
    struct {
        struct {
            TPM2B_SENSITIVE_CREATE inSensitive;
            TPM2_HANDLE handle;
            struct {
                TPM2_ALG_ID type;
                TPM2_ALG_ID digest;
                TPM2_ALG_ID sign;
            } alg;
        } in;
        struct {
            const char *ctx_file;
            tpm2_convert_pubkey_fmt pub_fmt;
            const char *pub_file;
            const char *name_file;
            const char *priv_file;
        } out;
    } ak;
    struct {
        struct {
            TPMS_AUTH_COMMAND session_data;
            tpm2_session *session;
        } auth2;
    } owner;
    struct {
        UINT8 f : 1;
        UINT8 o : 1;
        UINT8 e : 1;
        UINT8 P : 1;
        UINT8 unused : 4;
    } flags;
    char *owner_auth_str;
    char *endorse_auth_str;
    char *ak_auth_str;
    bool find_persistent_ak;
};

static createak_context ctx = {
    .ak = {
        .in = {
            .alg = {
                .type = TPM2_ALG_RSA,
                .digest = TPM2_ALG_SHA256,
                .sign = TPM2_ALG_NULL
            },
        },
        .out = {
            .pub_fmt = pubkey_format_tss
        },
    },
    .ek = {
        .auth2 = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    },
    .owner = {
        .auth2 = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    },
    .flags = { 0 },
    .find_persistent_ak = false
};

/*
 * TODO: All these set_xxx_signing_algorithm() routines could likely somehow be refactored into one.
 */
static bool set_rsa_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg, TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_RSASSA;
    }

    in_public->publicArea.parameters.rsaDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_RSASSA :
    case TPM2_ALG_RSAPSS :
        in_public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The RSA signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_ecc_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_ECDSA;
    }

    in_public->publicArea.parameters.eccDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_ECDSA :
    case TPM2_ALG_SM2 :
    case TPM2_ALG_ECSCHNORR :
    case TPM2_ALG_ECDAA :
        in_public->publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The ECC signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_keyed_hash_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_HMAC;
    }

    in_public->publicArea.parameters.keyedHashDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_HMAC :
        in_public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR(
                "The Keyedhash signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_key_algorithm(TPM2B_PUBLIC *in_public)
{
    in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
    // First clear attributes bit field.
    in_public->publicArea.objectAttributes = 0;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    in_public->publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public->publicArea.authPolicy.size = 0;

    in_public->publicArea.type = ctx.ak.in.alg.type;

    switch(ctx.ak.in.alg.type)
    {
    case TPM2_ALG_RSA:
        in_public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        in_public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.keyBits = 2048;
        in_public->publicArea.parameters.rsaDetail.exponent = 0;
        in_public->publicArea.unique.rsa.size = 0;
        return set_rsa_signing_algorithm(ctx.ak.in.alg.sign, ctx.ak.in.alg.digest, in_public);
    case TPM2_ALG_ECC:
        in_public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
        in_public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        in_public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        in_public->publicArea.unique.ecc.x.size = 0;
        in_public->publicArea.unique.ecc.y.size = 0;
        return set_ecc_signing_algorithm(ctx.ak.in.alg.sign, ctx.ak.in.alg.digest, in_public);
    case TPM2_ALG_KEYEDHASH:
        in_public->publicArea.unique.keyedHash.size = 0;
        return set_keyed_hash_signing_algorithm(ctx.ak.in.alg.sign, ctx.ak.in.alg.digest, in_public);
    case TPM2_ALG_SYMCIPHER:
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx.ak.in.alg.type);
        return false;
    }

    return true;
}

static bool create_ak(TSS2_SYS_CONTEXT *sapi_context) {

    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {
        {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    }}};

    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;
    TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
    TPM2B_CREATION_DATA creation_data = TPM2B_EMPTY_INIT;

    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    bool result = set_key_algorithm(&inPublic);
    if (!result) {
        return false;
    }

    sessions_data.auths[0] = ctx.ek.auth2.session_data;

    tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_new(sapi_context, data);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(session);
    tpm2_session_free(&session);


    TPM2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(
            sapi_context,
            TPM2_RH_ENDORSEMENT,
            handle,
            &sessions_data,
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicySecret, rval);
        return false;
    }

    LOG_INFO("Tss2_Sys_PolicySecret succ");

    // Set up the session data for the handle used in PolicySecret.
    sessions_data.auths[0].sessionHandle = handle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, ctx.ek.ek_ctx.handle, &sessions_data,
            &ctx.ak.in.inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
            &out_public, &creation_data, &creation_hash, &creation_ticket,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Create, rval);
        return false;
    }
    LOG_INFO("TPM2_Create succ");

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }

    sessions_data.auths[0] = ctx.ek.auth2.session_data;

    data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return false;
    }

    session = tpm2_session_new(sapi_context, data);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    handle = tpm2_session_get_handle(session);
    tpm2_session_free(&session);

    rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM2_RH_ENDORSEMENT,
            handle, &sessions_data, 0, 0, 0, 0, 0, 0, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicySecret, rval);
        return false;
    }
    LOG_INFO("Tss2_Sys_PolicySecret succ");

    // Set up the session data for the handle used in PolicySecret.
    sessions_data.auths[0].sessionHandle = handle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    TPM2_HANDLE loaded_sha1_key_handle;
    rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sapi_context, ctx.ek.ek_ctx.handle, &sessions_data, &out_private,
            &out_public, &loaded_sha1_key_handle, &name, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Load, rval);
        return false;
    }

    /* Output in YAML format */
    tpm2_tool_output("loaded-key:\n");
    tpm2_tool_output("  handle: 0x%X\n  name: ", loaded_sha1_key_handle);
    tpm2_util_print_tpm2b((TPM2B *)&name);
    tpm2_tool_output("\n");

    // write name to ak.name file
    if (ctx.ak.out.name_file) {
        result = files_save_bytes_to_file(ctx.ak.out.name_file, &name.name[0], name.size);
        if (!result) {
            LOG_ERR("Failed to save AK name into file \"%s\"", ctx.ak.out.name_file);
            return false;
        }
    }

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }

    // use the owner auth here.
    sessions_data.auths[0] = ctx.owner.auth2.session_data;

    if (ctx.ak.in.handle) {

        rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, TPM2_RH_OWNER, loaded_sha1_key_handle,
                &sessions_data, ctx.ak.in.handle, &sessions_data_out));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_EvictControl, rval);
            return false;
        }
        LOG_INFO("EvictControl: Make AK persistent succ.");

        rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, loaded_sha1_key_handle));
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_FlushContext, rval);
            return false;
        }
        LOG_INFO("Flush transient AK succ.");
    } else if (ctx.ak.out.ctx_file) {
        bool result = files_save_tpm_context_to_path_sapi(sapi_context,
                loaded_sha1_key_handle, ctx.ak.out.ctx_file);
        if (!result) {
            LOG_ERR("Error saving tpm context for handle");
            return false;
        }
    }

    if (ctx.ak.out.pub_file) {
        result = tpm2_convert_pubkey_save(&out_public, ctx.ak.out.pub_fmt,
                ctx.ak.out.pub_file);
        if (!result) {
            return false;
        }
    }

    if (ctx.ak.out.priv_file) {
        result = files_save_private(&out_private, ctx.ak.out.priv_file);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'C':
        ctx.ek.ctx_arg = value;
        break;
    case 'k':
        if (!strcmp(value, "-")) {
            ctx.find_persistent_ak = true;
        } else {
            result = tpm2_util_string_to_uint32(value, &ctx.ak.in.handle);
            if (!result) {
                LOG_ERR("Could not convert persistent AK handle.");
                return false;
            }
        }
        break;
    case 'G':
        ctx.ak.in.alg.type = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_base);
        if (ctx.ak.in.alg.type == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert algorithm. got: \"%s\".", value);
            return false;
        }
        break;
    case 'D':
        ctx.ak.in.alg.digest = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.ak.in.alg.digest == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert digest algorithm.");
            return false;
        }
        break;
    case 's':
        ctx.ak.in.alg.sign = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_sig);
        if (ctx.ak.in.alg.sign == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert signing algorithm.");
            return false;
        }
        break;
    case 'o':
        ctx.flags.o = 1;
        ctx.owner_auth_str = value;
        break;
    case 'e':
        ctx.flags.e = 1;
        ctx.endorse_auth_str = value;
        break;
    case 'P': 
        ctx.flags.P = 1;
        ctx.ak_auth_str = value;
        break;
    case 'p':
        ctx.ak.out.pub_file = value;
        break;
    case 'n':
        ctx.ak.out.name_file = value;
        break;
    case 'f':
        ctx.ak.out.pub_fmt = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.ak.out.pub_fmt == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = true;
        break;
    case 'c':
        ctx.ak.out.ctx_file = value;
        break;
    case 'r':
        ctx.ak.out.priv_file = value;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "auth-owner",     required_argument, NULL, 'o' },
        { "auth-endorse",   required_argument, NULL, 'e' },
        { "auth-ak",        required_argument, NULL, 'P' },
        { "ek-context",     required_argument, NULL, 'C' },
        { "ak-handle",      required_argument, NULL, 'k' },
        { "algorithm",      required_argument, NULL, 'G' },
        { "digest-alg",     required_argument, NULL, 'D' },
        { "sign-alg",       required_argument, NULL, 's' },
        { "file",           required_argument, NULL, 'p' },
        { "ak-name",        required_argument, NULL, 'n' },
        { "format",         required_argument, NULL, 'f' },
        { "context",        required_argument, NULL, 'c' },
        { "privfile",       required_argument, NULL, 'r'},
    };

    *opts = tpm2_options_new("o:C:e:k:G:D:s:P:f:n:p:c:r:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    bool ret;
    UNUSED(flags);

    if (ctx.flags.f && !ctx.ak.out.pub_file) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return -1;
    }

    if (ctx.find_persistent_ak) {
        ret = tpm2_capability_find_vacant_persistent_handle(sapi_context,
                        &ctx.ak.in.handle);
        if (!ret) {
            LOG_ERR("ak-handle/k passed with a value of '-' but unable to find"
                    " a vacant persistent handle!");
            return 1;
        }
        tpm2_tool_output("ak-persistent-handle: 0x%x\n", ctx.ak.in.handle);
    }

    ret = tpm2_util_object_load(sapi_context, ctx.ek.ctx_arg, &ctx.ek.ek_ctx);
    if (!ret) {
        return 1;
    }

    if (ctx.flags.o) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.owner_auth_str,
                &ctx.owner.auth2.session_data, &ctx.owner.auth2.session);
        if (!res) {
            LOG_ERR("Invalid owner authorization, got\"%s\"", ctx.owner_auth_str);
            return 1;
        }
    }

    if (ctx.flags.e) {
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.endorse_auth_str,
                &ctx.ek.auth2.session_data, &ctx.ek.auth2.session);
        if (!res) {
            LOG_ERR("Invalid endorse authorization, got\"%s\"",
                ctx.endorse_auth_str);
            return 1;
        }
    }
    if (ctx.flags.P) {
        TPMS_AUTH_COMMAND tmp;
        bool res = tpm2_auth_util_from_optarg(sapi_context, ctx.ak_auth_str,
                &tmp, NULL);
        if (!res) {
            LOG_ERR("Invalid AK authorization, got\"%s\"", ctx.ak_auth_str);
            return 1;
        }
        ctx.ak.in.inSensitive.sensitive.userAuth = tmp.hmac;
    } 
    return !create_ak(sapi_context);
}
