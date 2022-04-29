/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Part of this file is copied from tpm2-tss-engine.
 *
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 * Copyright (c) 2019, Wind River Systems.
 * All rights reserved.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <tss2/tss2_mu.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"

#define OID_loadableKey "2.23.133.10.1.3"

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;

DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY);
DECLARE_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY);

ASN1_SEQUENCE(TSSPRIVKEY) = {
	ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
	ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)

#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY);
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);

typedef struct tpm_encodeobject_ctx tpm_encodeobject_ctx;
struct tpm_encodeobject_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    struct {
        const char *pubpath;
        TPM2B_PUBLIC public;
        const char *privpath;
        TPM2B_PRIVATE private;
        ESYS_TR handle;
    } object;

    char *output_path;
};

static tpm_encodeobject_ctx ctx;

static bool on_option(char key, char *value) {
    switch (key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'u':
        ctx.object.pubpath = value;
        break;
    case 'r':
        ctx.object.privpath = value;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'o':
	ctx.output_path = value;
	break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {
    const struct option topts[] = {
      { "auth",           required_argument, NULL, 'P' },
      { "public",         required_argument, NULL, 'u' },
      { "private",        required_argument, NULL, 'r' },
      { "parent-context", required_argument, NULL, 'C' },
      { "output",         required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("P:u:r:C:o:", ARRAY_LEN(topts), topts, on_option,
            NULL, 0);

    return *opts != NULL;
}

static tool_rc check_opts(void) {
    tool_rc rc = tool_rc_success;
    if (!ctx.parent.ctx_path) {
        LOG_ERR("Expected parent object via -C");
        rc = tool_rc_option_error;
    }

    if (!ctx.object.pubpath) {
        LOG_ERR("Expected public object portion via -u");
        rc = tool_rc_option_error;
    }

    if (!ctx.object.privpath) {
        LOG_ERR("Expected private object portion via -r");
        rc = tool_rc_option_error;
    }

    if (!ctx.output_path) {
        LOG_ERR("Expected output file path via -o");
        rc = tool_rc_option_error;
    }

    return rc;
}

static tool_rc init(ESYS_CONTEXT *ectx) {
    bool res = files_load_public(ctx.object.pubpath, &ctx.object.public);
    if (!res) {
        return tool_rc_general_error;
    }

    res = files_load_private(ctx.object.privpath, &ctx.object.private);
    if (!res) {
        return tool_rc_general_error;
    }

    return tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false,
            TPM2_HANDLE_ALL_W_NV);
}

static int
encode(void)
{
    TSS2_RC rc;
    BIO *bio = NULL;
    TSSPRIVKEY *tpk = NULL;

    uint8_t private_buf[sizeof(ctx.object.private)];
    uint8_t public_buf[sizeof(ctx.object.public)];
    size_t private_len = 0, public_len = 0;

    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(&ctx.object.private, private_buf,
				       sizeof(private_buf), &private_len);
    if (rc) {
        LOG_ERR("Error serializing private portion of object");
        goto error;
    }

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(&ctx.object.public, public_buf,
				      sizeof(public_buf), &public_len);
    if (rc) {
        LOG_ERR("Error serializing public portion of object");
        goto error;
    }

    tpk = TSSPRIVKEY_new();
    if (!tpk) {
        LOG_ERR("oom");
        goto error;
    }

    tpk->type = OBJ_txt2obj(OID_loadableKey, 1);
    if (!tpk->type) {
        LOG_ERR("oom");
        goto error;
    }

    tpk->emptyAuth = ctx.parent.auth_str == NULL ? true : false;

    if ((ctx.parent.object.handle >> TPM2_HR_SHIFT) == TPM2_HT_PERSISTENT) {
	ASN1_INTEGER_set(tpk->parent, ctx.parent.object.handle);
    } else {
	/* Indicate that the parent is a primary object generated on the fly. */
	ASN1_INTEGER_set(tpk->parent, TPM2_RH_OWNER);
    }

    ASN1_STRING_set(tpk->privkey, private_buf, private_len);
    ASN1_STRING_set(tpk->pubkey, public_buf, public_len);

    if ((bio = BIO_new_file(ctx.output_path, "w")) == NULL) {
	LOG_ERR("Could not open file: \"%s\"", ctx.output_path);
        goto error;
    }

    PEM_write_bio_TSSPRIVKEY(bio, tpk);
    TSSPRIVKEY_free(tpk);
    BIO_free(bio);

    return tool_rc_success;
 error:
    if (bio)
        BIO_free(bio);
    if (tpk)
        TSSPRIVKEY_free(tpk);
    return tool_rc_general_error;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    tool_rc rc = check_opts();
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return encode();
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("encodeobject", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
