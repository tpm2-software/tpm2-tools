/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define RSA_EK_NONCE_NV_INDEX 0x01c00003
#define RSA_EK_TEMPLATE_NV_INDEX 0x01c00004
#define ECC_EK_NONCE_NV_INDEX 0x01c0000b
#define ECC_EK_TEMPLATE_NV_INDEX 0x01c0000c

typedef struct createek_context createek_context;
struct createek_context {

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_owner_hierarchy;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_endorse_hierarchy;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_ek;

    tpm2_hierarchy_pdata objdata;
    char *out_file_path;
    tpm2_convert_pubkey_fmt format;
    struct {
        UINT8 f :1;
        UINT8 t :1;
    } flags;

    bool find_persistent_handle;
};

static createek_context ctx = {
    .format = pubkey_format_tss,
    .objdata = TPM2_HIERARCHY_DATA_INIT,
    .flags = { 0 },
    .find_persistent_handle = false
};

static bool set_key_algorithm(TPM2B_PUBLIC *input_public) {

    switch (input_public->publicArea.type) {
    case TPM2_ALG_RSA:
        input_public->publicArea.parameters.rsaDetail.symmetric.algorithm =
                TPM2_ALG_AES;
        input_public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        input_public->publicArea.parameters.rsaDetail.symmetric.mode.aes =
                TPM2_ALG_CFB;
        input_public->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        input_public->publicArea.parameters.rsaDetail.keyBits = 2048;
        input_public->publicArea.parameters.rsaDetail.exponent = 0;
        input_public->publicArea.unique.rsa.size = 256;
        break;
    case TPM2_ALG_KEYEDHASH:
        input_public->publicArea.parameters.keyedHashDetail.scheme.scheme =
                TPM2_ALG_XOR;
        input_public->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg =
                TPM2_ALG_SHA256;
        input_public->publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf =
                TPM2_ALG_KDF1_SP800_108;
        input_public->publicArea.unique.keyedHash.size = 0;
        break;
    case TPM2_ALG_ECC:
        input_public->publicArea.parameters.eccDetail.symmetric.algorithm =
                TPM2_ALG_AES;
        input_public->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        input_public->publicArea.parameters.eccDetail.symmetric.mode.sym =
                TPM2_ALG_CFB;
        input_public->publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        input_public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        input_public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        input_public->publicArea.unique.ecc.x.size = 32;
        input_public->publicArea.unique.ecc.y.size = 32;
        break;
    case TPM2_ALG_SYMCIPHER:
        input_public->publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
        input_public->publicArea.parameters.symDetail.sym.keyBits.aes = 128;
        input_public->publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
        input_public->publicArea.unique.sym.size = 0;
        break;
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!",
                input_public->publicArea.type);
        return false;
    }

    return true;
}

static tool_rc set_ek_template(ESYS_CONTEXT *ectx, TPM2B_PUBLIC *input_public) {
    TPM2_HANDLE template_nv_index;
    TPM2_HANDLE nonce_nv_index;

    switch (input_public->publicArea.type) {
    case TPM2_ALG_RSA:
        template_nv_index = RSA_EK_TEMPLATE_NV_INDEX;
        nonce_nv_index = RSA_EK_NONCE_NV_INDEX;
        break;
    case TPM2_ALG_ECC:
        template_nv_index = ECC_EK_TEMPLATE_NV_INDEX;
        nonce_nv_index = ECC_EK_NONCE_NV_INDEX;
        break;
    default:
        LOG_ERR("EK template and EK nonce for algorithm type input(%4.4x)"
                " are not supported!", input_public->publicArea.type);
        return tool_rc_general_error;
    }

    UINT8* template = NULL;
    UINT8* nonce = NULL;

    // Read EK template
    UINT16 template_size;
    tool_rc rc = tpm2_util_nv_read(ectx, template_nv_index, 0, 0,
        &ctx.auth_owner_hierarchy.object, &template, &template_size, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    TSS2_RC ret = Tss2_MU_TPMT_PUBLIC_Unmarshal(template, template_size,
    NULL, &input_public->publicArea);
    if (ret != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to unmarshal TPMT_PUBLIC from buffer 0x%p", template);
        rc = tool_rc_general_error;
        goto out;
    }

    // Read EK nonce
    UINT16 nonce_size;
    rc = tpm2_util_nv_read(ectx, nonce_nv_index, 0, 0,
        &ctx.auth_owner_hierarchy.object, &nonce, &nonce_size, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    if (input_public->publicArea.type == TPM2_ALG_RSA) {
        memcpy(&input_public->publicArea.unique.rsa.buffer, &nonce, nonce_size);
        input_public->publicArea.unique.rsa.size = 256;
    } else {
        // ECC is only other supported algorithm
        memcpy(&input_public->publicArea.unique.ecc.x.buffer, &nonce, nonce_size);
        input_public->publicArea.unique.ecc.x.size = 32;
        input_public->publicArea.unique.ecc.y.size = 32;
    }

    out: if (template) {
        free(template);
    }

    if (nonce) {
        free(nonce);
    }

    return rc;
}

static tool_rc create_ek_handle(ESYS_CONTEXT *ectx) {

    if (ctx.flags.t) {
        tool_rc rc = set_ek_template(ectx, &ctx.objdata.in.public);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else {
        bool result = set_key_algorithm(&ctx.objdata.in.public);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tpm2_hierarchy_create_primary(ectx,
        ctx.auth_endorse_hierarchy.object.session, &ctx.objdata, NULL);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.auth_ek.object.handle) {

        rc = tpm2_ctx_mgmt_evictcontrol(ectx, ESYS_TR_RH_OWNER,
                ctx.auth_owner_hierarchy.object.session, ctx.objdata.out.handle,
                ctx.auth_ek.object.handle, NULL);
        if (rc != tool_rc_success) {
            return rc;
        }

        rc = tpm2_flush_context(ectx, ctx.objdata.out.handle);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else {
        /* If it wasn't persistent, save a context for future tool interactions */
        tool_rc rc = files_save_tpm_context_to_path(ectx,
                ctx.objdata.out.handle, ctx.auth_ek.ctx_path);
        if (rc != tool_rc_success) {
            LOG_ERR("Error saving tpm context for handle");
            return rc;
        }
    }

    if (ctx.out_file_path) {
        bool ok = tpm2_convert_pubkey_save(ctx.objdata.out.public, ctx.format,
                ctx.out_file_path);
        if (!ok) {
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.auth_endorse_hierarchy.auth_str = value;
        break;
    case 'w':
        ctx.auth_owner_hierarchy.auth_str = value;
        break;
    case 'p':
        ctx.auth_ek.auth_str = value;
        break;
    case 'G': {
        TPMI_ALG_PUBLIC type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_base);
        if (type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got \"%s\"", value);
            return false;
        }
        ctx.objdata.in.public.publicArea.type = type;
    }
        break;
    case 'u':
        if (!value) {
            LOG_ERR("Please specify an output file to save the pub ek to.");
            return false;
        }
        ctx.out_file_path = value;
        break;
    case 'f':
        ctx.format = tpm2_convert_pubkey_fmt_from_optarg(value);
        if (ctx.format == pubkey_format_err) {
            return false;
        }
        ctx.flags.f = true;
        break;
    case 'c':
        ctx.auth_ek.ctx_path = value;
        break;
    case 't':
        ctx.flags.t = true;
        break;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "eh-auth",              required_argument, NULL, 'P' },
        { "owner-auth",           required_argument, NULL, 'w' },
        { "key-algorithm",        required_argument, NULL, 'G' },
        { "public",               required_argument, NULL, 'u' },
        { "format",               required_argument, NULL, 'f' },
        { "ek-context",           required_argument, NULL, 'c' },
        { "template",             no_argument,       NULL, 't' },
    };

    *opts = tpm2_options_new("P:w:G:u:f:c:t", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
}

static void set_default_obj_attrs(void) {

    ctx.objdata.in.public.publicArea.objectAttributes =
      TPMA_OBJECT_RESTRICTED  | TPMA_OBJECT_ADMINWITHPOLICY
    | TPMA_OBJECT_DECRYPT     | TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
}

static void set_default_auth_policy(void) {

    static const TPM2B_DIGEST auth_policy = {
        .size = 32,
        .buffer = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
        }
    };

    TPM2B_DIGEST *authp = &ctx.objdata.in.public.publicArea.authPolicy;
    *authp = auth_policy;
}

static void set_default_hierarchy(void) {
    ctx.objdata.in.hierarchy = TPM2_RH_ENDORSEMENT;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    size_t i;
    tool_rc rc = tool_rc_general_error;

    tpm2_session **sessions[] = {
#if 0
       &ctx.auth.ek.session,
       &ctx.auth.endorse.session,
       &ctx.auth.owner.session,
#endif
       &ctx.auth_owner_hierarchy.object.session,
       &ctx.auth_endorse_hierarchy.object.session,
       &ctx.auth_ek.object.session,
    };

    if (ctx.flags.f && !ctx.out_file_path) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return tool_rc_option_error;
    }

    if (!ctx.auth_ek.ctx_path) {
        LOG_ERR("Expected option -c");
        return tool_rc_option_error;
    }

    bool ret;
    if (!strcmp(ctx.auth_ek.ctx_path, "-")) {
        /* If user passes a handle of '-' we try and find a vacant slot for
         * to use and tell them what it is.
         */
        rc = tpm2_capability_find_vacant_persistent_handle(ectx,
                false, &ctx.auth_ek.object.handle);
        if (rc != tool_rc_success) {
            LOG_ERR("handle/-H passed with a value '-' but unable to find a"
                    " vacant persistent handle!");
            goto out;
        }
        tpm2_tool_output("persistent-handle: 0x%x\n", ctx.auth_ek.object.handle);
    } else {
        /* best attempt to convert what they have us to a handle, if it's not
         * a handle then we assume its a path to a context file */
        ret = tpm2_util_string_to_uint32(ctx.auth_ek.ctx_path, &ctx.auth_ek.object.handle);
        UNUSED(ret);
    }

    rc = tpm2_util_object_load_auth(ectx, "owner",
        ctx.auth_owner_hierarchy.auth_str, &ctx.auth_owner_hierarchy.object,
        false, TPM2_HANDLE_FLAGS_O);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid owner hierarchy authorization");
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, "endorsement",
        ctx.auth_endorse_hierarchy.auth_str, &ctx.auth_endorse_hierarchy.object,
        false, TPM2_HANDLE_FLAGS_E);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid endorsement hierarchy authorization");
        return rc;
    }

    /*
     * The ek object is created @create_ek_handle and so it isn't loaded here
     * The ek object attributes are setup to policy reference eh-auth
     */
    rc = tpm2_auth_util_from_optarg(ectx, ctx.auth_ek.auth_str,
            &ctx.auth_ek.object.session, false);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid EK authorization");
        goto out;
    }

    /* override the default attrs */
    set_default_obj_attrs();

    /* set the auth policy */
    set_default_auth_policy();

    /* set the default hierarchy */
    set_default_hierarchy();

    /* normalize 0 success 1 failure */
    rc = create_ek_handle(ectx);

out:
    for (i = 0; i < ARRAY_LEN(sessions); i++) {
        tpm2_session *s = *sessions[i];
        tool_rc tmp_rc = tpm2_session_close(&s);
        if (tmp_rc != tool_rc_success) {
            rc = tmp_rc;
        }
    }

    return rc;
}

static void tpm2_tool_onexit(void) {

    tpm2_hierarchy_pdata_free(&ctx.objdata);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("createek", tpm2_tool_onstart, tpm2_tool_onrun, NULL, tpm2_tool_onexit)
