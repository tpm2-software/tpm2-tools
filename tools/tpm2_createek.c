/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define RSA_EK_NONCE_NV_INDEX 0x01c00003
#define RSA_EK_TEMPLATE_NV_INDEX 0x01c00004
#define ECC_EK_NONCE_NV_INDEX 0x01c0000b
#define ECC_EK_TEMPLATE_NV_INDEX 0x01c0000c
#define ECC_SM2_EK_TEMPLATE_NV_INDEX 0x01c0001b

#define DEFAULT_KEY_ALG "rsa2048"

/* Templates from TCG EK Credential Profile TPM 2.0, Version 2.4 Rev. 3, 2021 */

#define ATTRS_A \
    TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT| \
    TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_ADMINWITHPOLICY| \
    TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT

#define ATTRS_B ATTRS_A|TPMA_OBJECT_USERWITHAUTH

static const TPM2B_DIGEST policy_a_sha256 = {
    .size = 32,
    .buffer = {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90,
        0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E,
        0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA
    }
};

static const TPM2B_DIGEST policy_b_sha384 = {
    .size = 48,
    .buffer = {
        0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC, 0x53, 0xD8,
        0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41, 0x48, 0xBB,
        0x35, 0xD3, 0xB4, 0xE4, 0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4,
        0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
        0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12
    }
};

static const TPM2B_DIGEST policy_b_sha512 = {
    .size = 64,
    .buffer = {
        0xB8, 0x22, 0x1C, 0xA6, 0x9E, 0x85, 0x50, 0xA4, 0x91, 0x4D,
        0xE3, 0xFA, 0xA6, 0xA1, 0x8C, 0x07, 0x2C, 0xC0, 0x12, 0x08,
        0x07, 0x3A, 0x92, 0x8D, 0x5D, 0x66, 0xD5, 0x9E, 0xF7, 0x9E,
        0x49, 0xA4, 0x29, 0xC4, 0x1A, 0x6B, 0x26, 0x95, 0x71, 0xD5,
        0x7E, 0xDB, 0x25, 0xFB, 0xDB, 0x18, 0x38, 0x42, 0x56, 0x08,
        0xB4, 0x13, 0xCD, 0x61, 0x6A, 0x5F, 0x6D, 0xB5, 0xB6, 0x07,
        0x1A, 0xF9, 0x9B, 0xEA
    }
};

static const TPM2B_DIGEST policy_b_sm3_256 = {
    .size = 32,
    .buffer = {
        0x16, 0x78, 0x60, 0xA3, 0x5F, 0x2C, 0x5C, 0x35, 0x67, 0xF9,
        0xC9, 0x27, 0xAC, 0x56, 0xC0, 0x32, 0xF3, 0xB3, 0xA6, 0x46,
        0x2F, 0x8D, 0x03, 0x79, 0x98, 0xE7, 0xA1, 0x0F, 0x77, 0xFA,
        0x45, 0x4A
    }
};

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

    const char *key_alg;
    tpm2_hierarchy_pdata objdata;
    char *out_file_path;
    tpm2_convert_pubkey_fmt format;
    bool autoflush;
    struct {
        UINT8 f :1;
        UINT8 t :1;
    } flags;

    bool find_persistent_handle;
};

static createek_context ctx = {
    .format = pubkey_format_tss,
    .key_alg = DEFAULT_KEY_ALG,
    .objdata = {
        .in = {
            .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
            .hierarchy = TPM2_RH_ENDORSEMENT
        },
    },
    .flags = { 0 },
    .find_persistent_handle = false,
    .autoflush = false
};

typedef struct alg_map alg_map;
struct alg_map {
   const char *input;
   const char *alg;
   const char *namealg;
   const TPM2B_DIGEST *policy;
   const TPMA_OBJECT attrs;
};

static const alg_map alg_maps[] = {
    { "rsa",           "rsa2048:aes128cfb", "sha256", &policy_a_sha256, ATTRS_A },
    { "rsa2048",       "rsa2048:aes128cfb", "sha256", &policy_a_sha256, ATTRS_A },
    { "rsa3072",       "rsa3072:aes256cfb", "sha384", &policy_b_sha384, ATTRS_B },
    { "rsa4096",       "rsa4096:aes256cfb", "sha384", &policy_b_sha384, ATTRS_B },
    { "ecc",           "ecc_nist_p256:aes128cfb", "sha256", &policy_a_sha256, ATTRS_A },
    { "ecc256",        "ecc_nist_p256:aes128cfb", "sha256", &policy_a_sha256, ATTRS_A },
    { "ecc384",        "ecc_nist_p384:aes256cfb", "sha384", &policy_b_sha384, ATTRS_B },
    { "ecc521",        "ecc_nist_p521:aes256cfb", "sha512", &policy_b_sha512, ATTRS_B },
    { "ecc_nist_p256", "ecc_nist_p256:aes128cfb", "sha256", &policy_a_sha256, ATTRS_A },
    { "ecc_nist_p384", "ecc_nist_p384:aes256cfb", "sha384", &policy_b_sha384, ATTRS_B },
    { "ecc_nist_p521", "ecc_nist_p521:aes256cfb", "sha512", &policy_b_sha512, ATTRS_B },
    { "ecc_sm2",       "ecc_sm2_p256:sm4_128cfb", "sm3_256", &policy_b_sm3_256, ATTRS_B },
    { "ecc_sm2_p256",  "ecc_sm2_p256:sm4_128cfb", "sm3_256", &policy_b_sm3_256, ATTRS_B },
    { "keyedhash",     "xor", "sha256", &policy_a_sha256, ATTRS_A },
};

static const alg_map *lookup_alg_map(const char *alg) {
    size_t i;

    for (i = 0; i < ARRAY_LEN(alg_maps); i++)
    {
        if (!strcmp(alg, alg_maps[i].input)) {
            return &alg_maps[i];
        }
    }
    return NULL;
}

static tool_rc init_ek_public(const char *key_alg, TPM2B_PUBLIC *public) {
    const alg_map *m = lookup_alg_map(key_alg);

    if (!m) {
        LOG_ERR("Invalid key algorithm, got \"%s\"", key_alg);
        return tool_rc_unsupported;
    }

    tool_rc rc = tpm2_alg_util_public_init(m->alg, m->namealg, NULL, NULL,
                                           m->attrs, public);
    if (rc != tool_rc_success) {
        return rc;
    }

    public->publicArea.authPolicy = *m->policy;

    if (public->publicArea.type == TPM2_ALG_ECC &&
        (public->publicArea.parameters.eccDetail.curveID == TPM2_ECC_NIST_P256 ||
         public->publicArea.parameters.eccDetail.curveID == TPM2_ECC_SM2_P256)) {
        public->publicArea.unique.ecc.x.size = 32;
        public->publicArea.unique.ecc.y.size = 32;
    } else  if (public->publicArea.type == TPM2_ALG_RSA &&
                public->publicArea.parameters.rsaDetail.keyBits == 2048) {
        public->publicArea.unique.rsa.size = 256;
    }
    return tool_rc_success;
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
        if (input_public->publicArea.parameters.eccDetail.curveID == TPM2_ECC_NIST_P256) {
            template_nv_index = ECC_EK_TEMPLATE_NV_INDEX;
            nonce_nv_index = ECC_EK_NONCE_NV_INDEX;
        } else if (input_public->publicArea.parameters.eccDetail.curveID == TPM2_ECC_SM2_P256) {
            template_nv_index = ECC_SM2_EK_TEMPLATE_NV_INDEX;
            // EK Nonces SHALL NOT be Populated in any NV Index in the High Range.
            nonce_nv_index = 0;
        } else {
            template_nv_index = ECC_EK_TEMPLATE_NV_INDEX;
            nonce_nv_index = ECC_EK_NONCE_NV_INDEX;
        }
        break;
    default:
        LOG_ERR("EK template and EK nonce for algorithm type input(%4.4x)"
                " are not supported!", input_public->publicArea.type);
        return tool_rc_general_error;
    }

    UINT8* template = NULL;
    UINT8* nonce = NULL;

    // Read EK template
    UINT16 template_size = 0;
    TPM2B_DIGEST cp_hash = { 0 };
    TPM2B_DIGEST rp_hash = { 0 };
    tool_rc rc = tpm2_util_nv_read(ectx, template_nv_index, 0, 0,
        &ctx.auth_owner_hierarchy.object, &template, &template_size, &cp_hash,
        &rp_hash, TPM2_ALG_SHA256, 0, ESYS_TR_NONE, ESYS_TR_NONE, NULL);
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

    // Check whether nonce exists
    if (nonce_nv_index) {
        TPMS_CAPABILITY_DATA *capabilities = NULL;

        rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES, nonce_nv_index,
                         1, NULL, &capabilities);
        if (rc != tool_rc_success) {
            goto out;
        }

        if (capabilities->data.tpmProperties.count == 0 ||
            capabilities->data.handles.handle[0] != nonce_nv_index) {
            free(capabilities);
            // The EK Template is used unmodified
            goto out;
        }
        free(capabilities);
    } else {
        // The EK Template is used unmodified
        goto out;
    }

    // Read EK nonce
    UINT16 nonce_size = 0;
    rc = tpm2_util_nv_read(ectx, nonce_nv_index, 0, 0,
                &ctx.auth_owner_hierarchy.object, &nonce, &nonce_size, &cp_hash,
                &rp_hash, TPM2_ALG_SHA256, 0, ESYS_TR_NONE, ESYS_TR_NONE, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    if (input_public->publicArea.type == TPM2_ALG_RSA) {
        if (nonce_size) {
            memcpy(&input_public->publicArea.unique.rsa.buffer, nonce, nonce_size);
            input_public->publicArea.unique.rsa.size = 256;
        }
    } else {
        // ECC is only other supported algorithm
        if (nonce_size) {
            memcpy(&input_public->publicArea.unique.ecc.x.buffer, nonce, nonce_size);
            input_public->publicArea.unique.ecc.x.size = 32;
            input_public->publicArea.unique.ecc.y.size = 32;
        }
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

    tool_rc rc = init_ek_public(ctx.key_alg, &ctx.objdata.in.public);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.flags.t) {
        tool_rc rc = set_ek_template(ectx, &ctx.objdata.in.public);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    rc = tpm2_create_primary(ectx, &ctx.auth_endorse_hierarchy.object,
        &ctx.objdata.in.sensitive, &ctx.objdata.in.public,
        &ctx.objdata.in.outside_info, &ctx.objdata.in.creation_pcr,
        &ctx.objdata.out.handle, &ctx.objdata.out.public,
        &ctx.objdata.out.creation.data, &ctx.objdata.out.hash,
        &ctx.objdata.out.creation.ticket, 0, TPM2_ALG_ERROR);
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

        rc = tpm2_flush_context(ectx, ctx.objdata.out.handle, NULL,
            TPM2_ALG_NULL);
        if (rc != tool_rc_success) {
            return rc;
        }
    } else {
        /* If it wasn't persistent, save a context for future tool interactions */
        tool_rc rc = files_save_tpm_context_to_path(ectx,
                     ctx.objdata.out.handle, ctx.auth_ek.ctx_path, ctx.autoflush);
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
        ctx.key_alg = tpm2_alg_util_numtoalgstr(value, tpm2_alg_util_flags_base);
        if (!ctx.key_alg) {
            LOG_ERR("Invalid key algorithm, got \"%s\"", value);
            return false;
        }
        break;
    }
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
    case 'R':
        ctx.autoflush = true;
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
        { "autoflush",            no_argument,       NULL, 'R' },
    };

    *opts = tpm2_options_new("P:w:G:u:f:c:tR", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != NULL;
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
